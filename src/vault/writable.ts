import { Credential, CredentialData } from '../credentials';
import { SecretValue } from '../secret-value';
import { ReadableVault, ReadableVaultOptions } from './readable';

export type UpdateCredentialInput = Partial<{
    data: Partial<CredentialData>;
    attachments: Record<string, SecretValue<Uint8Array> | null>;
    expiration: Date | null;
}>;

export interface WritableVaultOptions extends ReadableVaultOptions {
    /**
     * Open the vault in readonly mode. In this mode, you can't create, update, or delete
     * credentials.
     *
     * @default true
     */
    readonly: boolean;
}

export abstract class WritableVault<V> extends ReadableVault<V> {
    public writable = true;
    public readonly: boolean = true;

    constructor(options: Partial<WritableVaultOptions>) {
        super(options);
    }

    /**
     * Store a new credential in the vault.
     */
    public abstract createCredential(
        folder: string,
        name: string,
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
}
