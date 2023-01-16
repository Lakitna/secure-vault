import { Rule } from 'rulebound';
import { vaultRuleParameters } from '../../..';
import { detectPartialStringMatch } from '../../../../util/partial-string-match';

export function keepassVaultPasswordComplexityCharacterForbidVaultName() {
    return new Rule<vaultRuleParameters>('keepass/password/complexity/forbid-vault-name')
        .describe(
            `
            Ensure that the vault password does not contain part of the vault name.

            Attackers often use social engineering tactics to break a password. A common thing that
            user do, is to include (part of) a non-secret — like the vault name — in their
            passwords so it's easier to remember. Unfortunately, that also makes the password
            easier to break.

            Detection is done with fuzzy matching.
            `
        )
        .enable(async ({ config, vault, vaultCredential }) => {
            const forbidVaultName = config.vaultRestrictions.passwordComplexity.forbidVaultName;
            if (!forbidVaultName) {
                return 'Disabled by security config `forbidVaultName`';
            }

            const vaultName = vault.meta.name;
            if (!vaultName) {
                return 'No vault name, nothing to check';
            }

            const password = vaultCredential.password;
            if (password.length === 0) {
                return 'No vault password, nothing to check';
            }

            return true;
        })
        .define(async ({ vault, vaultCredential }) => {
            const vaultName = vault.meta.name as string;
            const password = vaultCredential.password;

            const match = detectPartialStringMatch(password, vaultName, 'strict');
            if (match) {
                throw new Error('Vault password contains (part of) the vault name');
            }

            return true;
        });
}
