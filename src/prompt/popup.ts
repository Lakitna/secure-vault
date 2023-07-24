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
 * For this to work, the Powershell part has to send the password back to the JS part. During
 * transit, the password is encrypted with RSA.
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

    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
    });

    const output = await promptUser(
        publicKeyToXml(publicKey),
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

    const decryptedPassword = decryptString(Buffer.from(output.password, 'base64'), privateKey);
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

/**
 * Powershell 5 only supports importing public keys in xml format.
 * Let's be accommodating and convert.
 *
 * Made possible by: https://stackoverflow.com/a/76744273/2963820
 */
function publicKeyToXml(publicKey: crypto.KeyObject): string {
    const jwk = publicKey.export({ format: 'jwk' });

    if (!jwk.n || !jwk.e) {
        throw new Error('Incomplete public key. How did you get here?');
    }

    const n = Buffer.from(jwk.n, 'base64url').toString('base64');
    const e = Buffer.from(jwk.e, 'base64url').toString('base64');

    return `<RSAKeyValue><Modulus>${n}</Modulus><Exponent>${e}</Exponent></RSAKeyValue>`;
}

function decryptString(encryptedBuffer: Buffer, privateKey: crypto.KeyObject): SecretValue<string> {
    const decryptedBuffer = crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_PADDING,
        },
        encryptedBuffer
    );

    return new SecretValue<string>('string', decryptedBuffer.toString('utf-8'));
}
