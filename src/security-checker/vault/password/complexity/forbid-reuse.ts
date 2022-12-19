import { Rule } from 'rulebound';
import { vaultRuleParameters } from '../../..';
import { createKeepassCredential } from '../../../../keepass/credential';

export function vaultPasswordComplexityCharacterForbidReuse() {
    return new Rule<vaultRuleParameters>('vault/password/complexity/forbid-reuse')
        .describe(
            `
            Ensure that the vault password is not used by a credential in the vault.

            Reusing the same password in different places puts you at a higher risk of having your
            accounts compromised. If a hacker is able to obtain your password, they will be able to
            access all of the accounts that use that password. Using a different password for each
            account protects from this type of attack.
            `
        )
        .enable(async ({ config, vaultCredential }) => {
            const forbidReuse = config.vaultRestrictions.passwordComplexity.forbidReuse;
            if (!forbidReuse) {
                return 'Disabled by security config `forbidReuse`';
            }

            const vaultPassword = vaultCredential.password;
            if (vaultPassword.length === 0) {
                return 'No vault password';
            }

            return true;
        })
        .define(async ({ vault, vaultCredential }) => {
            const vaultPassword = vaultCredential.password;

            const defaultGroup = vault.getDefaultGroup();
            const entries = [...defaultGroup.allEntries()];
            const credentials = entries.map((entry) => createKeepassCredential(entry));

            for (const credential of credentials) {
                const otherPassword = credential.data.password;

                if (!vaultPassword.equals(otherPassword)) {
                    // Not the same password.
                    continue;
                }

                throw new Error(
                    `Vault password is used by a credential: ` + `'${credential.path.join('/')}'`
                );
            }

            return true;
        });
}
