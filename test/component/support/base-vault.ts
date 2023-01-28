import { fileURLToPath } from 'node:url';
import { KeepassVault, SecretValue } from '../../../src';

export function getBaseVault() {
    const vault = new KeepassVault(
        fileURLToPath(new URL('base-test-vault.kdbx', import.meta.url)),
        { securityConfig: 'none' }
    );

    vault.securityConfig.prompt.method = async () => ({
        password: new SecretValue('string', 'test-vault-password'),
        savePassword: false,
    });

    return vault;
}
