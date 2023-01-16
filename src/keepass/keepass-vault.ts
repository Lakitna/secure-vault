import argon2 from 'argon2';
import camelcase from 'camelcase';
import { readFile, writeFile } from 'fs/promises';
import kdbxweb, { Kdbx } from 'kdbxweb';
import { RulebookConfig } from 'rulebound';
import { SecurityConfig, securityConfigPresetNames } from '../config/security';
import { VaultCredential } from '../config/vault-password-prompt';
import { Credential, CredentialData, CredentialWithoutSecrets } from '../credentials';
import { getRememberedPassword, rememberPassword } from '../prompt/remember-password';
import { SecretValue } from '../secret-value';
import { checkCredentialSecurity, checkVaultSecurity } from '../security-checker';
import { resolveSymlink } from '../util/resolve-symlink';
import { GetCredentialOptions, Vault } from '../vault';
import { createCredentialWithoutSecrets, createKeepassCredential } from './keepass-credential';

/**
 * The KDBX4 vault format uses Argon2 for password hashing. Kdbxweb does not support this out of
 * the box, so we need to add support ourselves.
 */
kdbxweb.CryptoEngine.setArgon2Impl(
    async (password, salt, memory, iterations, length, parallelism, type, version) => {
        const hash = await argon2.hash(Buffer.from(password), {
            type: type,
            hashLength: length,
            parallelism: parallelism,
            version: version,
            salt: Buffer.from(salt),
            memoryCost: memory,
            timeCost: iterations,
            raw: true,
        });
        return new Uint8Array(hash).buffer;
    }
);

interface KeepassVaultOptions {
    securityConfig: securityConfigPresetNames | Partial<SecurityConfig>;

    /**
     * Path to the keyfile used as a second authentication factor for the vault.
     */
    keyfilePath: string;

    /**
     * Open the vault in readonly mode. In this mode, you can't create, update, or delete
     * credentials.
     *
     * @default true
     */
    readonly: boolean;

    /**
     * @default 'info'
     */
    logLevel: RulebookConfig['verboseness'];
}

export class KeepassVault extends Vault {
    public path: string;
    public keyfilePath?: KeepassVaultOptions['keyfilePath'];
    private vault?: Kdbx;
    private openTries: number;

    constructor(keepassVaultPath: string, options: Partial<KeepassVaultOptions> = {}) {
        super(options);
        this.path = keepassVaultPath;
        this.keyfilePath = options.keyfilePath;
        this.openTries = 0;
    }

    public async open(): Promise<Kdbx> {
        if (this.vault) {
            return this.vault;
        }

        const vaultCredential = await this.getVaultCredential();

        const vaultPath = await resolveSymlink(vaultCredential.path);
        const vaultFile = await readFile(vaultPath).catch((err) => {
            console.error(err instanceof Error ? err.stack : err);
            throw new Error('Could not open vault');
        });

        let keyfile: ArrayBufferLike | undefined = undefined;
        if (vaultCredential.keyfilePath) {
            const keyfilePath = await resolveSymlink(vaultCredential.keyfilePath);
            keyfile = await readFile(keyfilePath)
                .then((file) => file.buffer)
                .catch((err) => {
                    console.error(err instanceof Error ? err.stack : err);
                    throw new Error('Could not open keyfile');
                });
        }

        const kdbxCredentials = new kdbxweb.Credentials(vaultCredential.password.value, keyfile);

        let vault;
        try {
            vault = await kdbxweb.Kdbx.load(vaultFile.buffer, kdbxCredentials);
        } catch (err) {
            if (this.openTries === 0 && this.securityConfig.allowPasswordSave) {
                console.log('Could not open vault. Retrying...');
                this.openTries++;
                return this.open();
            }

            console.error(err instanceof Error ? err.stack : err);
            throw new Error('Could not open the vault. This is probably a credentials issue');
        }

        await checkVaultSecurity(this.securityConfig, vault, vaultCredential);

        this.vault = vault;
        this.openTries = 0;
        return this.vault;
    }

    public async listCredentials(group?: string): Promise<CredentialWithoutSecrets[]> {
        const vault = await this.open();

        const defaultGroup = vault.getDefaultGroup();
        let entries = [...defaultGroup.allEntries()];

        if (group) {
            entries = entries.filter((entry) => {
                return group.toLowerCase() === (entry.parentGroup?.name ?? '').toLowerCase();
            });
        }

        return entries.map((entry) => createCredentialWithoutSecrets(entry));
    }

    public async getCredential(
        group: string,
        entryTitle: string,
        options?: GetCredentialOptions
    ): Promise<Credential | null> {
        const vault = await this.open();

        const defaultGroup = vault.getDefaultGroup();
        const entry = [...defaultGroup.allEntries()].find((entry) => {
            const groupName = (entry.parentGroup?.name ?? '').toLowerCase();
            const entryName = (entry.fields.get('Title')?.toString() || '').toLowerCase();
            return groupName === group.toLowerCase() && entryName === entryTitle.toLowerCase();
        });
        if (!entry) return null;

        const cred = createKeepassCredential(entry);
        if (options && options.secure === false) {
            await checkCredentialSecurity(this.securityConfig, cred, this);
        }
        return cred;
    }

    public async getCredentialById(
        uuid: string,
        options?: GetCredentialOptions
    ): Promise<Credential | null> {
        const vault = await this.open();
        const entry = await this.getEntryById(vault, uuid);
        if (!entry) return null;

        const cred = createKeepassCredential(entry);
        if (options && options.secure === false) {
            await checkCredentialSecurity(this.securityConfig, cred, this);
        }
        return cred;
    }

    public async createCredential(): Promise<Credential> {
        // TODO: Implement
        throw new Error('Not implemented');
    }

    public async updateCredential(
        credential: Credential,
        input: Partial<{
            data: Partial<CredentialData>;
            attachments: Record<string, SecretValue<Uint8Array> | null>;
            expiration: Date | null;
        }>
    ): Promise<void> {
        if (this.readonly) {
            throw new Error(`Vault was opened in readonly mode. Can't update credential.`);
        }

        const vault = await this.open();
        const entry = await this.getEntryById(vault, credential.id);
        if (!entry) {
            throw new Error(`Couldn't find credential by it's id: '${credential.path.join('/')}'`);
        }

        if (!input.data && !input.attachments && input.expiration === undefined) {
            return;
        }

        entry.pushHistory();

        if (input.data) {
            for (const [key, val] of Object.entries(input.data)) {
                const value = val instanceof SecretValue ? val.value : val;
                if (value === undefined) {
                    continue;
                }

                const casedKey =
                    key === 'url'
                        ? 'URL'
                        : key === 'username'
                        ? 'UserName'
                        : camelcase(key, { pascalCase: true });
                entry.fields.set(casedKey, value);
            }
        }

        if (input.attachments) {
            for (const [key, val] of Object.entries(input.attachments)) {
                const value = val instanceof SecretValue ? val.value : val;
                if (value === undefined) {
                    continue;
                }

                if (value === null) {
                    entry.binaries.delete(key);
                } else {
                    entry.binaries.set(key, value);
                }
            }
        }

        if (input.expiration !== undefined) {
            if (input.expiration === null) {
                entry.times.expires = false;
            } else {
                entry.times.expires = true;
                entry.times.expiryTime = input.expiration;
            }
        }

        entry.times.update();
    }

    public async deleteCredential(credential: Credential): Promise<void> {
        if (this.readonly) {
            throw new Error(`Vault was opened in readonly mode. Can't delete credential.`);
        }

        const vault = await this.open();
        const entry = await this.getEntryById(vault, credential.id);
        if (!entry) {
            throw new Error(`Couldn't find credential by it's id: '${credential.path.join('/')}'`);
        }

        vault.remove(entry);
    }

    public async save() {
        const vault = await this.open();

        const fileContent = await vault.save();
        const vaultPath = await resolveSymlink(this.path);

        await writeFile(vaultPath, Buffer.from(fileContent));
    }

    /**
     * Get the secrets to open the vault.
     */
    private async getVaultCredential(): Promise<VaultCredential> {
        // Only use remembered vault password on the first try. Otherwise we'll get stuck in an
        // infinite loop of bad vault passwords.
        if (this.openTries === 0 && this.securityConfig.allowPasswordSave) {
            const rememberedPass = await getRememberedPassword(this.path);
            if (rememberedPass instanceof SecretValue) {
                console.log('Using remembered vault password');
                return {
                    path: this.path,
                    keyfilePath: this.keyfilePath,
                    password: rememberedPass,
                    savePassword: false,
                };
            }
        }

        const vaultCredential = await this.securityConfig.passwordPromptMethod(
            this.path,
            this.keyfilePath,
            this.securityConfig.allowPasswordSave,
            this.securityConfig.passwordSaveDefault
        );

        if (vaultCredential.savePassword) {
            await rememberPassword(vaultCredential.path, vaultCredential.password);
            console.log('✅ Saved password');
        }

        return vaultCredential;
    }

    private async getEntryById(
        vault: kdbxweb.Kdbx,
        uuid: string
    ): Promise<kdbxweb.KdbxEntry | null> {
        const defaultGroup = vault.getDefaultGroup();
        const entry = [...defaultGroup.allEntries()].find((entry) => {
            return entry.uuid.valueOf() === uuid;
        });
        if (!entry) {
            return null;
        }
        return entry;
    }
}
