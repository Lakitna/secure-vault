import keytar from 'keytar';
import path from 'node:path';
import { SecretValue } from '../secret-value';

const serviceName = 'secure-vault';

export async function rememberPassword(
    vaultPath: string,
    password: SecretValue<string>
): Promise<void> {
    return keytar.setPassword(serviceName, path.normalize(vaultPath), password.expose());
}

export async function getRememberedPassword(
    vaultPath: string
): Promise<SecretValue<string> | null> {
    const password = await keytar.getPassword(serviceName, path.normalize(vaultPath));
    if (!password) {
        return null;
    }
    return new SecretValue('string', password);
}
