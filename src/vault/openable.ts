import { BaseVaultCredential } from '../config/vault-password-prompt.ts';
import { SecretValue } from '../secret-value.ts';
import {
    forgetRememberedPassword,
    getRememberedPassword,
    rememberPassword,
} from '../util/remember-password.ts';
import { EnforcableVault, EnforcableVaultOptions } from './enforcable.ts';

export interface VaultConnectionDetails {
    vaultPath: string;
    multifactor?: string;
}

export type OpenableVaultOptions = EnforcableVaultOptions;

export abstract class OpenableVault<V = unknown> extends EnforcableVault {
    public openable = true;

    constructor(options: Partial<OpenableVaultOptions> = {}) {
        super(options);
    }

    /**
     * Open the vault. Will prompt the user for credentials when required.
     *
     * Use this function if you want control over when the user is prompted for credentials.
     */
    public abstract open(): Promise<V>;

    /**
     * Get the secrets to open the vault using the prompt method.
     */
    public async getVaultCredential(
        vaultConnectionDetails: VaultConnectionDetails,
        firstAttempt: boolean,
        boundUserPrompt: () => Promise<BaseVaultCredential>
    ): Promise<BaseVaultCredential> {
        // Only use remembered vault password on the first try. Otherwise we'll get stuck in an
        // infinite loop of bad vault passwords.
        if (firstAttempt) {
            const rememberedPassword = await this.getRememberedPassword(this.id);
            if (rememberedPassword instanceof SecretValue) {
                console.log('Using remembered vault password');
                return {
                    password: rememberedPassword,
                    savePassword: false,
                    vaultPath: vaultConnectionDetails.vaultPath,
                    multifactor: vaultConnectionDetails.multifactor,
                };
            }
        }

        const vaultCredential = await boundUserPrompt();
        if (vaultCredential.savePassword) {
            await rememberPassword(vaultConnectionDetails.vaultPath, vaultCredential.password);
            console.log('✅ Remembered vault password');
        }

        return vaultCredential;
    }

    private async getRememberedPassword(vaultId: string) {
        if (!this.securityConfig.prompt.allowPasswordSave) {
            // Clear a potentially stored password to reduce the chance of it lingering after
            // config change.
            await forgetRememberedPassword(vaultId);
            return;
        }

        return await getRememberedPassword(vaultId);
    }
}
