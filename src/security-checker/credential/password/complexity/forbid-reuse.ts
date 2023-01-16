import { Rule } from 'rulebound';
import { credentialRuleParameters } from '../../..';
import { Credential } from '../../../../credentials';
import { Vault } from '../../../../vault';

export function credentialPasswordComplexityForbidReuse() {
    return new Rule<credentialRuleParameters>('credential/password/complexity/forbid-reuse')
        .describe(
            `
            Ensure that the credential password is not used by another credential in the vault.

            Reusing the same password in different places puts you at a higher risk of having your
            accounts compromised. If a hacker is able to obtain your password, they will be able to
            access all of the accounts that use that password. Using a different password for each
            account protects from this type of attack.
            `
        )
        .enable(async ({ config, credential }) => {
            const forbidReuse = config.credentialRestrictions.passwordComplexity.forbidReuse;
            if (!forbidReuse) {
                return 'Disabled by security config `forbidReuse`';
            }

            const thisPassword = credential.data.password;
            if (thisPassword.length === 0) {
                return 'No password, nothing to check';
            }

            return true;
        })
        .define(async ({ vault, credential }) => {
            const thisPassword = credential.data.password;

            const otherCredentials = await getOtherCredentials(vault, credential);

            for (const otherCredential of otherCredentials) {
                const otherPassword = otherCredential.data.password;

                if (!thisPassword.equals(otherPassword)) {
                    // Not the same password.
                    continue;
                }

                throw new Error(
                    `Credential password is used by another credential: ` +
                        `'${otherCredential.path.join('/')}'`
                );
            }

            return true;
        });
}

async function getOtherCredentials(vault: Vault, credential: Credential) {
    const withoutSecrets = (await vault.listCredentials()).filter(
        (other) => other.id !== credential.id
    );

    const otherCredentials = await Promise.all(
        withoutSecrets.map(({ id }) => {
            return vault.getCredentialById(id, { secure: false });
        })
    );

    return otherCredentials.filter((cred): cred is Credential => cred !== null);
}
