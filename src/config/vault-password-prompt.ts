import { promptCli } from '../prompt/cli';
import { promptEnvironmentVariable } from '../prompt/env';
import { promptPopup } from '../prompt/popup';
import { SecretValue } from '../secret-value';
import { VaultPasswordPromptConfig } from './security';

export type vaultPasswordPromptPresetNames = keyof typeof vaultPasswordPromptPresets;

export type userPasswordPrompt = (
    keepassVaultPath: string,
    keyfilePath: string | undefined,
    promptConfig: VaultPasswordPromptConfig
) => Promise<BaseVaultCredential>;

export interface BaseVaultCredential {
    password: SecretValue<string>;
    savePassword: boolean;
}

export const vaultPasswordPromptPresets = {
    /**
     * Prompt the user from the command line.
     *
     * Supports remembering vault password.
     */
    cli: promptCli,
    /**
     * Popup a small window to prompt the user.
     *
     * Windows only.
     * Supports remembering vault password.
     */
    popup: promptPopup,
    /**
     * Don't prompt the user, grab the vault password from the environment variables instead.
     *
     * Pipeline friendly.
     * Does not support remembering vault password.
     */
    env: promptEnvironmentVariable,
    /**
     * Don't prompt the user, grab the vault password from the environment variables instead.
     *
     * Pipeline friendly.
     * Does not support remembering vault password.
     */
    environmentVariable: promptEnvironmentVariable,
} as const;
