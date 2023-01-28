import c from 'ansi-colors';
import prompts from 'prompts';
import { VaultPasswordPromptConfig } from '../config/security';
import { BaseVaultCredential, userPasswordPrompt } from '../config/vault-password-prompt';
import { SecretValue } from '../secret-value';

export const promptCli: userPasswordPrompt = async function (
    keepassVaultPath: string,
    keyfilePath: string | undefined,
    promptConfig: VaultPasswordPromptConfig
): Promise<BaseVaultCredential> {
    const questions: prompts.PromptObject<
        'vaultPath' | 'keyfilePath' | 'password' | 'savePassword'
    >[] = [
        {
            type: 'password',
            name: 'password',
            message: 'KeePass vault password',
        },
    ];

    if (promptConfig.allowPasswordSave) {
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
            choices: promptConfig.passwordSaveDefault
                ? [choiceYes, choiceNo]
                : [choiceNo, choiceYes],
        });
    }

    console.clear();
    consoleLine();
    console.log('Please provide Keepass vault credentials');
    consoleLine();
    console.log();
    console.log(`${c.gray('»')} Keepass vault path ${c.gray('...')} ${keepassVaultPath}`);
    console.log(`${c.gray('»')} Keepass keyfile path ${c.gray('...')} ${keyfilePath}`);
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
        password: new SecretValue<string>('string', response.password as string),
        savePassword: (response.savePassword as boolean | undefined) ?? false,
    };
};

function consoleLine() {
    console.log('-'.repeat(process.stdout.columns - 1));
}
