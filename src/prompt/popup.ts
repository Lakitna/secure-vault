import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { VaultPasswordPromptConfig } from '../config/security';
import { BaseVaultCredential, userPasswordPrompt } from '../config/vault-password-prompt';
import { SecretValue } from '../secret-value';

// TODO: The current approach is Windows only. See if we can support MacOS and Linux too.
//       Low priority
// MacOS: Might be able to do this with Automator

/**
 * Open up a popup window to prompt the user for credentials.
 *
 * There are two parts to this prompt method:
 * 1. The JS part
 * 2. The Powershell part, to render the popup itself
 *
 * For this to work, the Powershell part has to send the password back to the JS part. This is an
 * inherently insecure approach. To make it less aweful there is some encryption involved:
 *
 * - An encryption key is generated in the JS part and passed to Powershell in plaintext.
 * - The Powershell part encrypts the password given by the user with the key.
 * - The encrypted password is returned to the JS part where it is decrypted with the key.
 *
 * This is still not secure since the encryption key is send in plaintext. But it is better than
 * passing the password around in plaintext. An attacker with access to your machine will be able
 * to snatch and decrypt the password.
 */
export const promptPopup: userPasswordPrompt = async function (
    keepassVaultPath: string,
    keyfilePath: string | undefined,
    promptConfig: VaultPasswordPromptConfig
): Promise<BaseVaultCredential> {
    const isWindows = process.platform === 'win32';
    if (!isWindows) {
        console.log(
            `The popup prompt looks simple to make, but it requires OS specific things. ` +
                `This makes it quite difficult to make a cross-OS popup prompt. ` +
                `Please use a different prompt method, like 'cli' which works on any OS.`
        );
        throw new Error(`The password prompt method 'popup' is only supported on Windows`);
    }

    const encryptionKey = crypto.randomBytes(32);

    const output = await promptUser(
        encryptionKey.toString('base64'),
        keepassVaultPath,
        keyfilePath,
        promptConfig.allowPasswordSave,
        promptConfig.passwordSaveDefault
    );

    if (
        typeof output.vault !== 'string' ||
        typeof output.keyfile !== 'string' ||
        typeof output.save !== 'boolean' ||
        typeof output.password !== 'string' ||
        Object.keys(output).length !== 4
    ) {
        throw new Error('Child process output has unexpected format. This should never happen');
    }
    if (output.vault !== keepassVaultPath || output.keyfile !== keyfilePath) {
        throw new Error('Child process changed vault or keyfile path. This should never happen');
    }

    const decryptedPassword = await decryptString(
        Buffer.from(output.password, 'base64'),
        encryptionKey
    );
    return {
        password: decryptedPassword,
        savePassword: output.save,
        vaultPath: keepassVaultPath,
        multifactor: keyfilePath,
    };
};

async function promptUser(
    encryptionKey: string,
    keepassVaultPath: string,
    keyfilePath: string | undefined,
    allowPasswordSave: boolean,
    passwordSaveDefault: boolean
): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
        const dir = path.dirname(fileURLToPath(import.meta.url));
        const args = [
            path.join(dir, 'popup-prompt.ps1'),
            `'${encryptionKey}'`,
            `'${keepassVaultPath}'`,
            `'${keyfilePath}'`,
            `${allowPasswordSave}`,
            `${passwordSaveDefault}`,
        ];
        const process = spawn('powershell', args);

        let output: undefined | Record<string, unknown>;

        let stdout = '';
        process.stdout.on('data', (data) => {
            try {
                output = JSON.parse(data.toString());
            } catch {
                stdout += data.toString();
            }
        });

        let stderr = '';
        process.stderr.on('data', (data) => {
            stderr += data.toString();
        });

        process.on('exit', (code) => {
            if (code !== 0) {
                console.error('Child process exited with code ' + code);
                return reject(new Error('Something went wrong while prompting for Vault password'));
            }

            if (stderr) {
                console.log(stderr);
                return reject(new Error('Child process unexpectedly output to stderr'));
            }
            if (stdout) {
                console.log(stdout);
                return reject(new Error('Child process unexpectedly output to stdout'));
            }

            if (!output) {
                return reject(new Error('Child process exited, but did not return'));
            }

            if (output.cancel === true) {
                return reject(new Error('User canceled the password prompt'));
            }

            resolve(output);
        });
    });
}

function decryptString(encryptedBuffer: Buffer, keyBuffer: Buffer): Promise<SecretValue<string>> {
    const ivBuffer = encryptedBuffer.subarray(0, 16);
    const dataBuffer = encryptedBuffer.subarray(16);

    const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuffer, ivBuffer);
    decipher.setAutoPadding(false);

    return new Promise((resolve, reject) => {
        let decrypted = '';

        decipher.on('readable', () => {
            let chunk;
            while (null !== (chunk = decipher.read())) {
                decrypted += chunk.toString('utf-8').replaceAll('\x00', '');
            }
        });
        decipher.on('error', (err) => {
            reject(err);
        });

        decipher.write(dataBuffer);
        decipher.end();

        resolve(new SecretValue<string>('string', decrypted));
    });
}
