import argon2 from 'argon2';
import camelcase from 'camelcase';
import { readFile, writeFile } from 'fs/promises';
import kdbxweb, { Kdbx } from 'kdbxweb';
import { RulebookConfig } from 'rulebound';
import {
    ResolvedSecurityConfig,
    resolveSecurityConfig,
    SecurityConfig,
    securityConfigPresetNames,
} from '../config/security';
import { VaultCredential } from '../config/vault-password-prompt';
import { getRememberedPassword, rememberPassword } from '../prompt/remember-password';
import { SecretValue } from '../secret-value';
import { checkCredentialSecurity, checkVaultSecurity } from '../security-checker';
import { resolveSymlink } from '../util/resolve-symlink';
import {
    createKeepassCredential,
    createKeepassCredentialWithoutSecrets,
    KeepassCredential,
    KeepassCredentialData,
    KeepassCredentialWithoutSecrets,
} from './credential';

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
    keyfilePath: string;
    /**
     * Open the vault in readonly mode. In this mode, you can't create, update, or delete
     * credentials.
     */
    readonly: boolean;
    logLevel: RulebookConfig['verboseness'];
}

export class KeepassVault {
    public path: string;
    public securityConfig: ResolvedSecurityConfig;
    public keyfilePath?: KeepassVaultOptions['keyfilePath'];
    public readonly: KeepassVaultOptions['readonly'];
    public logLevel?: KeepassVaultOptions['logLevel'];
    private vault?: Kdbx;
    private openTries: number;

    constructor(keepassVaultPath: string, options: Partial<KeepassVaultOptions> = {}) {
        this.path = keepassVaultPath;
        this.keyfilePath = options.keyfilePath;
        this.securityConfig = resolveSecurityConfig(options.securityConfig);
        this.openTries = 0;
        this.readonly = options.readonly ?? true;
        this.logLevel = options.logLevel;
    }

    /**
     * Open the vault. Will prompt the user for credentials when required.
     *
     * Use this function if you want control over when the user is prompted for credentials.
     */
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

    /**
     * List all credentials without secrets
     *
     * @param group List only credentials in this group instead. Case insensitive.
     */
    public async listCredentials(group?: string): Promise<KeepassCredentialWithoutSecrets[]> {
        const vault = await this.open();

        const defaultGroup = vault.getDefaultGroup();
        let entries = [...defaultGroup.allEntries()];

        if (group) {
            entries = entries.filter((entry) => {
                return group.toLowerCase() === (entry.parentGroup?.name ?? '').toLowerCase();
            });
        }

        return entries.map((entry) => createKeepassCredentialWithoutSecrets(entry));
    }

    /**
     * List all credentials with secrets.
     *
     * Note: No security checks will be performed. You probably don't want to use this.
     *
     * @param group List only credentials in this group instead. Case insensitive.
     */
    public async listCredentialsWithSecrets(group?: string): Promise<KeepassCredential[]> {
        const vault = await this.open();

        const defaultGroup = vault.getDefaultGroup();
        let entries = [...defaultGroup.allEntries()];

        if (group) {
            entries = entries.filter((entry) => {
                return group.toLowerCase() === (entry.parentGroup?.name ?? '').toLowerCase();
            });
        }

        return entries.map((entry) => createKeepassCredential(entry));
    }

    /**
     * Get a credential from the vault.
     *
     * @param group Case insensitive
     * @param entryTitle Case insensitive
     */
    public async getCredential(
        group: string,
        entryTitle: string
    ): Promise<KeepassCredential | null> {
        const vault = await this.open();

        const defaultGroup = vault.getDefaultGroup();
        const entry = [...defaultGroup.allEntries()].find((entry) => {
            const groupName = (entry.parentGroup?.name ?? '').toLowerCase();
            const entryName = (entry.fields.get('Title')?.toString() || '').toLowerCase();
            return groupName === group.toLowerCase() && entryName === entryTitle.toLowerCase();
        });
        if (!entry) return null;

        const cred = createKeepassCredential(entry);
        await checkCredentialSecurity(this.securityConfig, cred, this);
        return cred;
    }

    /**
     * Get a credential from the vault.
     */
    public async getCredentialById(uuid: string): Promise<KeepassCredential | null> {
        const vault = await this.open();
        const entry = await this.getEntryById(vault, uuid);
        if (!entry) return null;

        const cred = createKeepassCredential(entry);
        await checkCredentialSecurity(this.securityConfig, cred, this);
        return cred;
    }

    // TODO: Add create
    // public async createCredential(input: {
    //     data?: Partial<KeepassCredentialData>,
    //     attachments?: Record<string, SecretValue<Uint8Array>>,
    //     expiration?: Date
    // }): Promise<KeepassCredential> {

    // }

    /**
     * Update a credential.
     *
     * Don't forget to save the vault afterwards.
     */
    public async updateCredential(
        credential: KeepassCredential,
        input: Partial<{
            data: Partial<KeepassCredentialData>;
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

    /**
     * Delete a credential.
     *
     * Don't forget to save the vault afterwards.
     */
    public async deleteCredential(credential: KeepassCredential): Promise<void> {
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

    private async getVaultCredential(): Promise<VaultCredential> {
        // Only use remembered master password on the first try. Otherwise we'll get stuck in an
        // infinite loop of bad master passwords.
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
