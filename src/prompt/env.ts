import kdbx from 'kdbxweb';
import { BaseVaultCredential, userPasswordPrompt } from '../config/vault-password-prompt';
import { SecretValue } from '../secret-value';

export const promptEnvironmentVariable: userPasswordPrompt = async function (
    keepassVaultPath: string,
    keyfilePath: string | undefined
): Promise<BaseVaultCredential> {
    let vault = process.env.KEEPASS_VAULT_PATH;
    if (!vault) {
        console.log('Missing environment variable KEEPASS_VAULT_PATH, using config value:');
        vault = keepassVaultPath;
        console.log('  ' + vault);
    }

    let keyfile = process.env.KEEPASS_VAULT_KEYFILE_PATH;
    if (!keyfile) {
        console.log('Missing environment variable KEEPASS_VAULT_KEYFILE_PATH, using config value:');
        keyfile = keyfilePath;
        console.log('  ' + keyfile);
    }

    const password = process.env.KEEPASS_VAULT_PASSWORD;
    if (!password) {
        throw new Error('Missing environment variable KEEPASS_VAULT_PASSWORD');
    }

    return {
        password: new SecretValue<string>('string', kdbx.ProtectedValue.fromString(password)),
        savePassword: false,
    };
};
