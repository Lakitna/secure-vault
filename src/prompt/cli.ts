import { accessSync, constants } from 'node:fs';
import prompts from 'prompts';
import { userPasswordPrompt, VaultCredential } from '../config/vault-password-prompt';
import { SecretValue } from '../secret-value';

export const promptCli: userPasswordPrompt = async function (
    keepassVaultPath: string,
    keyfilePath: string | undefined,
    allowPasswordSave: boolean,
    passwordSaveDefault: boolean
): Promise<VaultCredential> {
    const questions: prompts.PromptObject<
        'vaultPath' | 'keyfilePath' | 'password' | 'savePassword'
    >[] = [
        {
            type: 'text',
            name: 'vaultPath',
            message: 'KeePass vault path',
            initial: keepassVaultPath,
            validate: (input: string) => {
                try {
                    accessSync(input, constants.R_OK);
                    return true;
                } catch {
                    return 'File does not exist';
                }
            },
        },
        {
            type: 'text',
            name: 'keyfilePath',
            message: 'KeePass keyfile path',
            initial: keyfilePath,
            validate: (input: string) => {
                if (input === '') {
                    return true;
                }
                try {
                    accessSync(input, constants.R_OK);
                    return true;
                } catch {
                    return 'File does not exist';
                }
            },
        },
        {
            type: 'password',
            name: 'password',
            message: 'KeePass vault password',
        },
    ];

    if (allowPasswordSave) {
        const choiceYes = {
            title: 'Yes',
            value: true,
            description: 'Remember vault password in OS credential manager',
        };
        const choiceNo = {
            title: 'No',
            value: false,
            description: `Don't remember vault password`,
        };

        questions.push({
            type: 'select',
            name: 'savePassword',
            message: 'Remember password?',
            choices: passwordSaveDefault ? [choiceYes, choiceNo] : [choiceNo, choiceYes],
        });
    }

    console.clear();
    consoleLine();
    console.log('Please provide KeePass vault credentials');
    consoleLine();
    console.log();
    const response = await prompts(questions, {
        onSubmit: () => {
            console.log();
        },
        onCancel: () => {
            throw new Error('Prompt not completed');
        },
    });
    consoleLine();

    return {
        path: response.vaultPath as string,
        keyfilePath: response.keyfilePath === '' ? undefined : (response.keyfilePath as string),
        password: new SecretValue<string>('string', response.password as string),
        savePassword: (response.savePassword as boolean | undefined) ?? false,
    };
};

function consoleLine() {
    console.log('-'.repeat(process.stdout.columns - 1));
}
