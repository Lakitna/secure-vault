import { Credential, KeepassVault, SecretValue } from '../../../src/index.ts';
import { CredentialRuleParameters } from '../../../src/vault/enforcable.ts';

export async function credentialRuleParam(vault: KeepassVault): Promise<CredentialRuleParameters> {
    const credential: Credential = {
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
