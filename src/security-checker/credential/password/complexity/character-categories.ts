import { Rule } from 'rulebound';
import { credentialRuleParameters } from '../../..';
import {
    characterCategories,
    countCharacterCategories,
} from '../../../../util/count-character-categories';

export function credentialPasswordComplexityCharacterCategories() {
    return new Rule<credentialRuleParameters>(
        'credential/password/complexity/min-character-categories'
    )
        .describe(
            `
            Require the credential password to have at least 1 character of different character
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
                config.credentialRestrictions.passwordComplexity.minCharacterCategories;
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
        .define(({ config, credential }) => {
            const minCharacterCategories =
                config.credentialRestrictions.passwordComplexity.minCharacterCategories;
            if (minCharacterCategories === 1) {
                // Always true, no need to compute
                return true;
            }

            const exposedPassword = credential.data.password.expose();
            const categoryCount = countCharacterCategories(exposedPassword);

            if (categoryCount < minCharacterCategories) {
                throw new Error(
                    `Credential password not complex enough. ` +
                        `Should contain at least ${minCharacterCategories} characters categories ` +
                        `but only contains ${categoryCount}.`
                );
            }

            return true;
        });
}
