import { fileURLToPath } from 'node:url';
import { KeepassVault, SecretValue } from '../../../src';

export function getBaseVault() {
    const vaultPath = fileURLToPath(new URL('base-test-vault.kdbx', import.meta.url));
    const vault = new KeepassVault(vaultPath, { securityConfig: 'none' });

    vault.securityConfig.prompt.method = async () => ({
        password: new SecretValue('string', 'test-vault-password'),
        savePassword: false,
        vaultPath: vaultPath,
        multifactor: undefined,
    });

    return vault;
}
