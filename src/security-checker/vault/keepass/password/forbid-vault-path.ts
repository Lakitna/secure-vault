import { Rule } from 'rulebound';
import { vaultRuleParameters } from '../../..';
import { detectPartialStringMatch } from '../../../../util/partial-string-match';

export function keepassVaultPasswordComplexityCharacterForbidVaultPath() {
    return new Rule<vaultRuleParameters>('keepass/password/complexity/forbid-vault-path')
        .describe(
            `
            Ensure that the vault password does not contain part of the vault file path.

            Attackers often use social engineering tactics to break a password. A common thing that
            user do, is to include (part of) a non-secret — like the vault file path — in their
            passwords so it's easier to remember. Unfortunately, that also makes the password
            easier to break.

            Detection is done with fuzzy matching.
            `
        )
        .enable(async ({ config, vaultCredential }) => {
            const forbidVaultPath = config.vaultRestrictions.passwordComplexity.forbidVaultPath;
            if (!forbidVaultPath) {
                return 'Disabled by security config `forbidVaultPath`';
            }

            const password = vaultCredential.password;
            if (password.length === 0) {
                return 'No vault password, nothing to check';
            }

            return true;
        })
        .define(async ({ vaultCredential }) => {
            const vaultPath = vaultCredential.vaultPath;
            const password = vaultCredential.password;

            const match = detectPartialStringMatch(password, vaultPath, 'strict');
            if (match) {
                throw new Error('Vault password contains (part of) the vault file path');
            }

            return true;
        });
}
