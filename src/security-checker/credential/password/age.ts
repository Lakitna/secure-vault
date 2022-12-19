import { Rule } from 'rulebound';
import { credentialRuleParameters } from '../..';

export function credentialPasswordAge() {
    return new Rule<credentialRuleParameters>('credential/password/age')
        .describe(
            `
            Ensure that your credential password is not used too long.

            Over time, more and more people will know your password. Periodically changing it will
            ensure that only the right people will have access to the credential.

            It's common for teams to change members over time. Ideally, you would change every
            credential every time someone leaves the team, but we tend to forget such things.
            Periodically changing the password is a mitigation tactic to reduce the risk of old team
            members having access to things they are not allowed to.

            We humans are famously bad at assessing risks, causing us to accidentally expose secrets
            like credentials. If you use a password for a long time, the risk of it being exposed
            somewhere increases. Periodically changing the password is a mitigation tactic to reduce
            the risk of (accidental) password exposure.
            `
        )
        .enable(({ config }) => {
            const maxPasswordAge = config.credentialRestrictions.maxPasswordAge;
            if (maxPasswordAge <= 0) {
                throw new TypeError(
                    'Configuration error: Max password age can not be equal to or below 0. ' +
                        'If you want this rule to never throw an error, use Infinity.'
                );
            }

            return true;
        })
        .define(({ config, credential }) => {
            const maxPasswordAge = config.credentialRestrictions.maxPasswordAge;

            if (credential.passwordAge > maxPasswordAge) {
                throw new Error(`Credential password is too old, change it`);
            }

            return true;
        });
}
