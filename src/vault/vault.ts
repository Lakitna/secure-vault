export interface BaseVaultOptions {
    /**
     * Vault ID
     */
    id: string;
}

export abstract class BaseVault {
    public id: string = '[unknown]';

    public enforcable = false;
    public openable = false;
    public readable = false;
    public writable = false;

    constructor(options: Partial<BaseVaultOptions>) {
        this.id = options?.id ?? '[unknown]';
    }
}
