import { KeepassVault } from '../../../src';
import { vaultRuleParameters } from '../../../src/security-checker';

export async function vaultRuleParams(vault: KeepassVault): Promise<vaultRuleParameters> {
    return {
        config: vault.securityConfig,
        vault: await vault.open(),
        // @ts-expect-error Calling a private method here for testing purposes
        vaultCredential: await vault.getVaultCredential(),
    };
}
