import { Rule } from 'rulebound';
import { credentialRuleParameters } from '..';

export function credentialRequireExpiration() {
    return new Rule<credentialRuleParameters>('credential/require-expiration')
        .describe(
            `
            Require that a credential has an expiration date.

            Over time, more and more people will know your password. Periodically changing it will
            ensure that only the right people will have access to the credential.

            It's common for teams to change members over time. Ideally, you would change every
            credential every time someone leaves the team, but we tend to forget such things.
            Periodically changing the password is a mitigation tactic to reduce the risk of old team
            members having access to things they are not allowed to.

            We humans are famously bad at assessing risks, causing us to accidentally expose secrets
            like credentials. If you use a credential password for a long time, the risk of it
            being exposed somewhere increases. Periodically changing the password is a mitigation
            tactic to reduce the risk of (accidental) password exposure.
            `
        )
        .enable(({ config }) => {
            if (config.credentialRestrictions.requireExpiration === false) {
                return 'Disabled by security config `requireExpiration`';
            }
            return true;
        })
        .define(({ config, credential }) => {
            if (config.credentialRestrictions.requireExpiration === false) {
                return true;
            }
            return credential.hasExpiration;
        })
        .punishment(() => {
            throw new Error(`Credential has no exipiration date`);
        });
}
