import { VaultRules } from '../enforcable';
import { WritableVault, WritableVaultOptions } from '../writable';
import { fileVaultPasswordComplexityCharacterForbidVaultPath } from './rules/vault/password/forbid-vault-path';
import { fileVaultStoredWithCode } from './rules/vault/vault-stored-with-code';

export interface FileVaultOptions extends WritableVaultOptions {}

export abstract class FileVault<V> extends WritableVault<V> {
    public path: string;
    public vault?: V;

    constructor(vaultPath: string, options: Partial<FileVaultOptions> = {}) {
        if (!options.id) {
            options.id = vaultPath;
        }
        super(options);

        this.path = vaultPath;
    }

    /**
     * Save changes made to the vault.
     */
    abstract save(): Promise<void>;

    public extendVaultRules(rules: VaultRules) {
        rules.vault.add(fileVaultPasswordComplexityCharacterForbidVaultPath);
        rules.vault.add(fileVaultStoredWithCode);
        return super.extendVaultRules(rules);
    }
}
