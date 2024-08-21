import { Credential, CredentialWithoutSecrets } from '../credentials.ts';
import { OpenableVault, OpenableVaultOptions } from './openable.ts';

export type GetCredentialOptions = {
    /**
     * Should we perform security checks?
     *
     * You probably don't want to disable this.
     *
     * @default true
     */
    secure: boolean;
};
export const defaultGetCredentialOptions: GetCredentialOptions = {
    secure: true,
};

export interface ReadableVaultOptions extends OpenableVaultOptions {}

export abstract class ReadableVault<V = unknown> extends OpenableVault<V> {
    public readable = true;

    constructor(options: Partial<ReadableVaultOptions>) {
        super(options);
    }

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
}
