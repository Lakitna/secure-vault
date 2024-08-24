import { KeepassVault, SecretValue } from '../../../src/index.ts';
import { VaultRuleParameters } from '../../../src/vault/enforcable.ts';

export async function vaultRuleParams(vault: KeepassVault): Promise<VaultRuleParameters> {
    return {
        config: vault.securityConfig,
        vault: vault,
        vaultCredential: {
            password: new SecretValue<string>('string', ''),
            savePassword: false,
            vaultPath: vault.path,
            multifactor: vault.keyfilePath,
        },
    };
}
