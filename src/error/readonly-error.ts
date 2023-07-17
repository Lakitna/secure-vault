export class ReadonlyError extends Error {
    constructor(operation: string) {
        super(`Vault was opened in readonly mode. Can't ${operation}.`);
    }
}
