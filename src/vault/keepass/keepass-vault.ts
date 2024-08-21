import argon2 from 'argon2';
import camelcase from 'camelcase';
import { readFile, writeFile } from 'fs/promises';
import kdbxweb, { Kdbx, KdbxEntry } from 'kdbxweb';
import { BaseVaultCredential } from '../../config/vault-password-prompt.ts';
import { Credential, CredentialWithoutSecrets } from '../../credentials.ts';
import { ReadonlyError } from '../../error/readonly-error.ts';
import { SecretValue } from '../../secret-value.ts';
import { resolveSymlink } from '../../util/resolve-symlink.ts';
import { VaultRuleParameters, VaultRules } from '../enforcable.ts';
import { FileVault, FileVaultOptions } from '../file/file-vault.ts';
import { defaultGetCredentialOptions, GetCredentialOptions } from '../readable.ts';
import { UpdateCredentialInput } from '../writable.ts';
import { createCredentialWithoutSecrets, createKeepassCredential } from './keepass-credential.ts';
import { keepassVaultKeyfileRequire } from './rules/vault/keyfile/keyfile-require.ts';
import { keepassVaultKeyfileStoredWithCode } from './rules/vault/keyfile/keyfile-stored-with-code.ts';
import { keepassVaultPasswordComplexityCharacterForbidVaultName } from './rules/vault/password/forbid-vault-name.ts';
import { keepassVaultDecryptionTime } from './rules/vault/vault-decryption-time.ts';
import { keepassVaultStoredWithKeyfile } from './rules/vault/vault-stored-with-keyfile.ts';

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

interface KeepassVaultOptions extends FileVaultOptions {
    /**
     * Path to the keyfile used as a second authentication factor for the vault.
     */
    keyfilePath: string;
}

export interface VaultRuleParametersKeepass extends VaultRuleParameters {
    vault: KeepassVault;
}

export class KeepassVault extends FileVault<Kdbx> {
    public keyfilePath?: KeepassVaultOptions['keyfilePath'];
    private openTries: number;

    constructor(keepassVaultPath: string, options: Partial<KeepassVaultOptions> = {}) {
        super(keepassVaultPath, options);
        this.keyfilePath = options.keyfilePath;
        this.openTries = 0;
    }

    public async open(): Promise<Kdbx> {
        if (this.vault) {
            return this.vault;
        }

        const prompt = () =>
            this.securityConfig.prompt.method(
                this.path,
                this.keyfilePath,
                this.securityConfig.prompt
            );
        const vaultCredential = await this.getVaultCredential(
            {
                vaultPath: this.path,
                multifactor: this.keyfilePath,
            },
            this.openTries === 0,
            prompt
        );

        const keyfile = await this.openKeyfile(vaultCredential.multifactor);
        this.vault = await this.openVault(vaultCredential, keyfile);

        await this.enforceVaultRules({
            config: this.securityConfig,
            vault: this,
            vaultCredential: vaultCredential,
        });

        this.openTries = 0;
        return this.vault;
    }

    public extendVaultRules(rules: VaultRules) {
        const keepassRules = rules as VaultRules<VaultRuleParametersKeepass>;
        keepassRules.vault.add(keepassVaultKeyfileRequire);
        keepassRules.vault.add(keepassVaultKeyfileStoredWithCode);
        keepassRules.vault.add(keepassVaultPasswordComplexityCharacterForbidVaultName);
        keepassRules.vault.add(keepassVaultDecryptionTime);
        keepassRules.vault.add(keepassVaultStoredWithKeyfile);
        return super.extendVaultRules(keepassRules);
    }

    public async listCredentials(group?: string): Promise<CredentialWithoutSecrets[]> {
        const entries = await this.getAllEntries(group);
        return entries.map((entry) => createCredentialWithoutSecrets(entry));
    }

    private async getAllEntries(group?: string): Promise<KdbxEntry[]> {
        const vault = await this.open();

        const defaultGroup = vault.getDefaultGroup();
        let entries = [...defaultGroup.allEntries()];

        if (group) {
            entries = entries.filter((entry) => {
                return group.toLowerCase() === (entry.parentGroup?.name ?? '').toLowerCase();
            });
        }

        return entries;
    }

    public async getCredential(
        group: string,
        entryTitle: string,
        options?: GetCredentialOptions
    ): Promise<Credential | null> {
        const opts = Object.assign(
            {},
            defaultGetCredentialOptions,
            options
        ) as GetCredentialOptions;

        const vault = await this.open();

        const defaultGroup = vault.getDefaultGroup();
        const entry = [...defaultGroup.allEntries()].find((entry) => {
            const groupName = (entry.parentGroup?.name ?? '').toLowerCase();
            const entryName = (entry.fields.get('Title')?.toString() || '').toLowerCase();
            return groupName === group.toLowerCase() && entryName === entryTitle.toLowerCase();
        });
        if (!entry) return null;

        const cred = createKeepassCredential(entry);
        if (opts.secure !== false) {
            await this.enforceCredentialRules({
                config: this.securityConfig,
                vault: this,
                credential: cred,
            });
        }
        return cred;
    }

    public async getCredentialById(
        uuid: string,
        options?: GetCredentialOptions
    ): Promise<Credential | null> {
        const opts = Object.assign(
            {},
            defaultGetCredentialOptions,
            options
        ) as GetCredentialOptions;

        const vault = await this.open();
        const entry = await this.getEntryById(vault, uuid);
        if (!entry) return null;

        const cred = createKeepassCredential(entry);
        if (opts.secure !== false) {
            await this.enforceCredentialRules({
                config: this.securityConfig,
                vault: this,
                credential: cred,
            });
        }
        return cred;
    }

    public async createCredential(
        group: string,
        entryTitle: string,
        input: UpdateCredentialInput
    ): Promise<Credential> {
        if (this.readonly) {
            throw new ReadonlyError('create credential');
        }

        const vault = await this.open();
        const rootGroup = vault.getDefaultGroup();
        const vaultGroups = rootGroup.groups;

        let vaultGroup = vaultGroups.find((vaultGroup) => vaultGroup.name === group);
        if (vaultGroup === undefined) {
            vaultGroup = vault.createGroup(rootGroup, group);
        }

        const existingVaultEntry = vaultGroup.entries.find((vaultEntry) => {
            return vaultEntry.fields.get('Title')?.toString() === entryTitle;
        });
        if (existingVaultEntry !== undefined) {
            throw new Error(`Can't create credential. It already exists.`);
        }
        const vaultEntry = vault.createEntry(vaultGroup);

        if (!input.data) {
            input.data = {};
        }
        input['data']['title'] = entryTitle;

        await this.updateEntry(vaultEntry, input);

        try {
            const credential = await this.getCredentialById(vaultEntry.uuid.id, {
                secure: true,
            });
            if (credential === null) {
                throw new Error('Could not find created credential. This should never happen');
            }
            return credential;
        } catch (error: unknown) {
            throw new Error('Could not create credential', { cause: error });
        }
    }

    public async updateCredential(
        credential: Credential,
        input: UpdateCredentialInput
    ): Promise<void> {
        if (this.readonly) {
            throw new ReadonlyError('update credential');
        }

        const vault = await this.open();
        const entry = await this.getEntryById(vault, credential.id);
        if (!entry) {
            throw new Error(`Couldn't find credential by it's id: '${credential.path.join('/')}'`);
        }

        return this.updateEntry(entry, input);
    }

    public async deleteCredential(credential: Credential): Promise<void> {
        if (this.readonly) {
            throw new ReadonlyError('delete credential');
        }

        const vault = await this.open();
        const entry = await this.getEntryById(vault, credential.id);
        if (!entry) {
            throw new Error(`Couldn't find credential by it's id: '${credential.path.join('/')}'`);
        }

        vault.remove(entry);
    }

    public async save() {
        if (this.readonly) {
            throw new ReadonlyError('save vault');
        }

        const vault = await this.open();

        const fileContent = await vault.save();
        const vaultPath = await resolveSymlink(this.path);

        await writeFile(vaultPath, Buffer.from(fileContent));
    }

    private async openKeyfile(
        keyFilePath: string | undefined
    ): Promise<ArrayBufferLike | undefined> {
        if (!keyFilePath) {
            return;
        }

        keyFilePath = await resolveSymlink(keyFilePath);

        try {
            const file = await readFile(keyFilePath);
            return file.buffer;
        } catch (error: unknown) {
            throw new Error('Could not open keyfile', { cause: error });
        }
    }

    private async openVault(
        vaultCredential: BaseVaultCredential,
        keyfile: ArrayBuffer | undefined
    ) {
        const kdbxCredentials = new kdbxweb.Credentials(vaultCredential.password.value, keyfile);

        const vaultFilePath = await resolveSymlink(vaultCredential.vaultPath);
        const vaultFile = await readFile(vaultFilePath).catch((err) => {
            throw new Error('Could not open vault file', { cause: err });
        });

        try {
            const vault = await kdbxweb.Kdbx.load(vaultFile.buffer, kdbxCredentials);
            return vault;
        } catch (err) {
            if (this.openTries === 0 && this.securityConfig.prompt.allowPasswordSave) {
                console.log('Could not open vault. Retrying...');
                this.openTries++;
                return this.open();
            }

            throw new Error('Could not open the vault. This is probably a credentials issue', {
                cause: err,
            });
        }
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

    private async updateEntry(entry: kdbxweb.KdbxEntry, input: UpdateCredentialInput) {
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

                let casedKey;
                if (key === 'url') {
                    casedKey = 'URL';
                } else if (key === 'username') {
                    casedKey = 'UserName';
                } else {
                    casedKey = camelcase(key, { pascalCase: true });
                }

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

    public async getVaultPasswordLastChangeDate(): Promise<Date | null> {
        return this.vault?.meta.keyChanged ?? null;
    }

    public async getPasswordUseCount(password: SecretValue<string>): Promise<number> {
        const entries = await this.getAllEntries();

        const matchingEntries = entries.filter((kdbxEntry) => {
            const entryPassword = kdbxEntry.fields.get('Password')?.valueOf();
            if (!(entryPassword instanceof kdbxweb.ProtectedValue)) {
                return false;
            }

            return password.equals(new SecretValue('string', entryPassword));
        });

        return matchingEntries.length;
    }
}
