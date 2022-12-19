import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { userPasswordPrompt, VaultCredential } from '../config/vault-password-prompt';
import { SecretValue } from '../secret-value';

// TODO: The childprocess sends the password in base64 to here. See if it can be encrypted with a
//       OTP instead. The main thing to figure out is the Powershell-side encryption and how to
//       share the key.

// TODO: The current approach is Windows only. See if we can support MacOS and Linux too.
//       Low priority
// MacOS: Might be able to do this with Automator

export const promptPopup: userPasswordPrompt = async function (
    keepassVaultPath: string,
    keyfilePath: string | undefined,
    allowPasswordSave: boolean,
    passwordSaveDefault: boolean
): Promise<VaultCredential> {
    const isWindows = process.platform === 'win32';
    if (!isWindows) {
        console.log(
            `The popup prompt looks simple to make, but it requires OS specific things. ` +
                `This makes it quite difficult to make a cross-OS popup prompt. ` +
                `Please use a different prompt method, like 'cli' which works on any OS.`
        );
        throw new Error(`The password prompt method 'popup' is only supported on Windows`);
    }

    const output = await promptUser(
        keepassVaultPath,
        keyfilePath,
        allowPasswordSave,
        passwordSaveDefault
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

    return {
        path: output.vault,
        keyfilePath: output.keyfile,
        password: new SecretValue<string>(
            'string',
            Buffer.from(output.password, 'base64').toString('utf-8')
        ),
        savePassword: output.save,
    };
};

async function promptUser(
    keepassVaultPath: string,
    keyfilePath: string | undefined,
    allowPasswordSave: boolean,
    passwordSaveDefault: boolean
): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
        const dir = path.dirname(fileURLToPath(import.meta.url));
        const args = [
            path.join(dir, 'popup-prompt.ps1'),
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
                console.log(stdout);
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
