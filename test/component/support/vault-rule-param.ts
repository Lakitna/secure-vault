import { KeepassVault, SecretValue } from '../../../src';
import { vaultRuleParameters } from '../../../src/security-checker';

export async function vaultRuleParams(vault: KeepassVault): Promise<vaultRuleParameters> {
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
