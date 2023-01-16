import { Rule } from 'rulebound';
import { vaultRuleParameters } from '../..';

export function vaultPasswordAge() {
    return new Rule<vaultRuleParameters>('vault/password/age')
        .describe(
            `
            Ensure that your vault password is not used for too long.

            Over time, more and more people will know your password. Periodically changing it will
            ensure that only the right people will be able to access the vault.

            It's common for teams to change members. Ideally, you would change the vault password
            every time someone leaves the team, but we tend to forget such things. Periodically
            changing the password is a mitigation tactic to reduce the risk of old team members
            having access to things they are not allowed to see.

            We humans are famously bad at assessing risks, causing us to accidentally expose secrets
            like the vault password. If you use the vault password for a long time, the risk of it
            being exposed somewhere increases. Periodically changing the password is a mitigation
            tactic to reduce the risk of (accidental) password exposure.
            `
        )
        .enable(({ config }) => {
            const maxPasswordAge = config.vaultRestrictions.maxPasswordAge;
            if (maxPasswordAge <= 0) {
                throw new TypeError(
                    'Configuration error: Max password age can not be equal to or below 0'
                );
            }

            return true;
        })
        .define(({ config, vault }) => {
            const maxPasswordAge = config.vaultRestrictions.maxPasswordAge;
            if (maxPasswordAge === Infinity) {
                // Will always be true, no need to compute
                return true;
            }

            const passwordChanged = vault.meta.keyChanged;
            if (!passwordChanged) {
                throw new Error(
                    'Could not find when the vault password was last changed. Assuming the worst.'
                );
            }

            const passwordAge = toAge(passwordChanged);
            if (passwordAge > maxPasswordAge) {
                throw new Error(`Vault password is too old, change it`);
            }

            return true;
        });
}

function toAge(time: Date): number {
    const now = new Date();
    const hourInMilliseconds = 3600000;
    return (now.getTime() - time.getTime()) / hourInMilliseconds;
}
