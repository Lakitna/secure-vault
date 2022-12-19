import { Rule } from 'rulebound';
import { vaultRuleParameters } from '../../..';
import {
    characterCategories,
    countCharacterCategories,
} from '../../../../util/count-character-categories';

export function vaultPasswordComplexityCharacterCategories() {
    return new Rule<vaultRuleParameters>('vault/password/complexity/min-character-categories')
        .describe(
            `
            Require the vault password to have at least 1 character of different character
            categories.

            A password made from a larger set of potential characters is harder to break via brute
            force and more sophisticated attacks. Requiring more character categories is a
            mitigation tactic to prevent users from creating easy to break passwords.

            Categories:
            - Uppercase characters A-Z (Latin alphabet)
            - Lowercase characters a-z (Latin alphabet)
            - Digits 0-9
            - Special characters (!, $, #, %, etc.)
            `
        )
        .enable(({ config }) => {
            const minCharacterCategories =
                config.vaultRestrictions.passwordComplexity.minCharacterCategories;
            if (minCharacterCategories < 1) {
                throw new TypeError(
                    'Configuration error: Min character category count can not be below 1'
                );
            }

            if (minCharacterCategories > characterCategories.length) {
                throw new TypeError(
                    'Configuration error: Min character category count can not be above ' +
                        characterCategories.length
                );
            }

            return true;
        })
        .define(({ config, vaultCredential }) => {
            const minCharacterCategories =
                config.vaultRestrictions.passwordComplexity.minCharacterCategories;

            if (minCharacterCategories === 1) {
                // Assuming the password length is not 0, this is always true. No need to expose
                // the password.
                return true;
            }

            const exposedPassword = vaultCredential.password.expose();
            const categoryCount = countCharacterCategories(exposedPassword);

            if (categoryCount < minCharacterCategories) {
                throw new Error(
                    `Vault password not complex enough. ` +
                        `Should contain at least ${minCharacterCategories} characters categories ` +
                        `but only contains ${categoryCount}.`
                );
            }

            return true;
        });
}
