import { Rule } from 'rulebound';
import { credentialRuleParameters } from '../..';

export function credentialPasswordLength() {
    return new Rule<credentialRuleParameters>('credential/password/length')
        .describe(
            `
            Ensure that your credential password has a minimum length.

            A longer password is harder to break. Length is, by far, the best defense against
            cracking passwords through brute force and more sophisticated cracking attacks.

            If you struggle with creating a long enough password, try using a passphrase instead of
            a password. Example passphrase: 'correct-horse-battery-staple'
            `
        )
        .enable(({ config }) => {
            const minPasswordLength = config.credentialRestrictions.minPasswordLength;
            if (minPasswordLength < 0) {
                throw new TypeError('Configuration error: Min password length can not be below 0');
            }

            return true;
        })
        .define(({ config, credential }) => {
            const minPasswordLength = config.credentialRestrictions.minPasswordLength;

            if (credential.data.password.length < minPasswordLength) {
                throw new Error(
                    `Credential password too short. ` +
                        `Should be at least ${minPasswordLength} characters.`
                );
            }

            return true;
        });
}
