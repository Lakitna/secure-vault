import { RulebookConfig } from 'rulebound';
import {
    ResolvedSecurityConfig,
    resolveSecurityConfig,
    SecurityConfig,
    securityConfigPresetNames,
} from './config/security';
import { BaseVaultCredential } from './config/vault-password-prompt';
import { Credential, CredentialData, CredentialWithoutSecrets } from './credentials';
import { SecretValue } from './secret-value';
import {
    forgetRememberedPassword,
    getRememberedPassword,
    rememberPassword,
} from './util/remember-password';

export interface VaultOptions {
    securityConfig: securityConfigPresetNames | Partial<SecurityConfig>;

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

export type GetCredentialOptions = {
    /**
     * Don't execute security checks.
     *
     * You probably don't want to use this.
     *
     * @default true
     */
    secure: boolean;
};

export type UpdateCredentialInput = Partial<{
    data: Partial<CredentialData>;
    attachments: Record<string, SecretValue<Uint8Array> | null>;
    expiration: Date | null;
}>;

export abstract class Vault {
    public readonly: VaultOptions['readonly'];
    public securityConfig: ResolvedSecurityConfig;
    public logLevel: VaultOptions['logLevel'];

    constructor(options: Partial<VaultOptions> = {}) {
        this.readonly = options.readonly ?? true;
        this.securityConfig = resolveSecurityConfig(options.securityConfig);
        this.logLevel = options.logLevel ?? 'info';
    }

    /**
     * Open the vault. Will prompt the user for credentials when required.
     *
     * Use this function if you want control over when the user is prompted for credentials.
     */
    public abstract open(): Promise<unknown>;

    /**
     * List all credentials without secrets
     *
     * @param folder List only credentials in this folder instead. Case insensitive.
     */
    public abstract listCredentials(folder?: string): Promise<CredentialWithoutSecrets[]>;

    /**
     * Get a credential from the vault.
     *
     * @param folder Case insensitive
     * @param entryTitle Case insensitive
     */
    public abstract getCredential(
        folder: string,
        entryTitle: string,
        options?: GetCredentialOptions
    ): Promise<Credential | null>;

    /**
     * Get a credential from the vault.
     */
    public abstract getCredentialById(
        id: string,
        options?: GetCredentialOptions
    ): Promise<Credential | null>;

    /**
     * Store a new credential in the vault.
     */
    public abstract createCredential(
        folder: string,
        entryTitle: string,
        input: UpdateCredentialInput
    ): Promise<Credential>;

    /**
     * Update an existing credential.
     */
    public abstract updateCredential(
        credential: Credential,
        input: UpdateCredentialInput
    ): Promise<void>;

    /**
     * Delete a credential.
     */
    public abstract deleteCredential(credential: Credential): Promise<void>;

    /**
     * Get the secrets to open the vault using the prompt method.
     */
    public async getVaultCredential(
        vaultId: string,
        firstAttempt: boolean,
        boundUserPrompt: () => Promise<BaseVaultCredential>
    ): Promise<BaseVaultCredential> {
        // Only use remembered vault password on the first try. Otherwise we'll get stuck in an
        // infinite loop of bad vault passwords.
        if (firstAttempt) {
            if (this.securityConfig.prompt.allowPasswordSave) {
                const rememberedPass = await getRememberedPassword(vaultId);
                if (rememberedPass instanceof SecretValue) {
                    console.log('Using remembered vault password');
                    return {
                        password: rememberedPass,
                        savePassword: false,
                    };
                }
            } else {
                // Clear a potentially stored password to reduce the chance of it lingering after
                // config change.
                await forgetRememberedPassword(vaultId);
            }
        }

        const vaultCredential = await boundUserPrompt();
        if (vaultCredential.savePassword) {
            await rememberPassword(vaultId, vaultCredential.password);
            console.log('✅ Remembered vault password');
        }

        return vaultCredential;
    }
}
