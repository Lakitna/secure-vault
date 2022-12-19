import { KeepassCredential, KeepassVault, SecretValue } from '../../../src';
import { credentialRuleParameters } from '../../../src/security-checker';

export async function credentialRuleParam(vault: KeepassVault): Promise<credentialRuleParameters> {
    const credential: KeepassCredential = {
        id: 'test-cred-1',
        expired: false,
        hasExpiration: false,
        passwordAge: 0,
        data: {
            title: 'test-cred-title',
            username: 'test-cred-user',
            password: new SecretValue<string>('string', 'test-cred-password'),
            url: '',
            notes: '',
        },
        attachments: {},
        path: ['Root', 'test-cred-title'],
    };

    return { config: vault.securityConfig, credential, vault };
}
