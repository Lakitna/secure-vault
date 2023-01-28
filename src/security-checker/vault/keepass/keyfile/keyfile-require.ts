import { Rule } from 'rulebound';
import { vaultRuleParameters } from '../../..';

export function keepassVaultKeyfileRequire() {
    return new Rule<vaultRuleParameters>('keepass/keyfile/require')
        .describe(
            `
            Enforce a keyfile as a second authentication factor.

            Multi-factor authentication (MFA) adds an extra layer of security to your vault. This
            makes it much harder for someone to gain unauthorized access to your vault, even if they
            have your vault password.

            Using MFA can protect you from a variety of attacks, such as phishing attempts and
            brute-force attacks. It can also help prevent unauthorized access to your vault if
            the master password is somehow compromised.
            `
        )
        .enable(({ config }) => {
            if (!config.vaultRestrictions.requireKeyfile) {
                return 'Disabled by security config `requireKeyfile`';
            }
            return true;
        })
        .define(({ vaultPaths }) => {
            return vaultPaths.keyfile !== undefined;
        })
        .punishment(() => {
            throw new Error(`Vault requires keyfile as second authentication factor`);
        });
}
