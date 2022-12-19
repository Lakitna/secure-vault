import { Rule } from 'rulebound';
import { vaultRuleParameters } from '../..';

export function vaultPasswordLength() {
    return new Rule<vaultRuleParameters>('vault/password/length')
        .describe(
            `
            Ensure that your vault password has a minimum length.

            A longer password is harder to break. Length is, by far, the best defense against
            cracking passwords through brute force as well as more sophisticated cracking attacks.

            If you struggle with creating a long enough password, try using a passphrase instead of
            a password. Example passphrase: 'correct-horse-battery-staple'
            `
        )
        .enable(({ config }) => {
            const minPasswordLength = config.vaultRestrictions.minPasswordLength;
            if (minPasswordLength < 0) {
                throw new TypeError('Configuration error: Min password length can not be below 0');
            }

            return true;
        })
        .define(({ config, vaultCredential }) => {
            const minPasswordLength = config.vaultRestrictions.minPasswordLength;
            const passwordLength = vaultCredential.password.length;

            if (passwordLength < minPasswordLength) {
                throw new Error(
                    `Vault password too short. ` +
                        `Should be at least ${minPasswordLength} characters.`
                );
            }

            return true;
        });
}
