import { KeepassVault, SecretValue } from '../../../src';
import { vaultRuleParameters } from '../../../src/security-checker';

export async function vaultRuleParams(vault: KeepassVault): Promise<vaultRuleParameters> {
    return {
        config: vault.securityConfig,
        vault: await vault.open(),
        vaultCredential: {
            password: new SecretValue<string>('string', ''),
            savePassword: false,
        },
        vaultPaths: {
            vault: vault.path,
            keyfile: vault.keyfilePath,
        },
    };
}
