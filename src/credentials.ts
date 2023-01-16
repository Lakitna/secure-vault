import { SecretValue } from './secret-value';

interface BaseCredential {
    /**
     * ID as assigned by the vault
     */
    id: string;
    /**
     * `true` if the credential has an expiration date
     */
    hasExpiration: boolean;
    /**
     * `true` if the the expiration date has passed.
     *
     * Always `false` when there is no expiration date.
     */
    expired: boolean;
    /**
     * Hours since the password was last changed
     */
    passwordAge: number;
    /**
     * Path to the credential inside the vault
     */
    path: string[];
}

interface BaseCredentialData {
    title: string;
    username: string;
    url: string;
    notes: string;
}

export interface CredentialWithoutSecrets extends BaseCredential {
    /**
     * The credential data itself. Will include username, title, etc.
     *
     * Will not contain any secret values.
     */
    data: CredentialDataWithoutSecrets;
}

export interface CredentialDataWithoutSecrets extends BaseCredentialData {
    [customAttribute: string]: string;
}

export interface Credential extends BaseCredential {
    /**
     * The credential data itself. Will include username, password, title, etc.
     *
     * Will also contain secret values.
     */
    data: CredentialData;
    /**
     * File attachments from the vault.
     */
    attachments: Record<string, SecretValue<Uint8Array>>;
}

export interface CredentialData extends BaseCredentialData {
    password: SecretValue<string>;
    [customAttribute: string]: string | SecretValue<string>;
}
