import { expect } from 'chai';
import Rulebook from 'rulebound';
import { SecretValue } from '../../../../../../src';
import { credentialRuleParameters } from '../../../../../../src/security-checker';
import { credentialPasswordComplexityForbidReuse } from '../../../../../../src/security-checker/credential/password/complexity/forbid-reuse';
import { getBaseVault } from '../../../../support/base-vault';
import { credentialRuleParam } from '../../../../support/credential-rule-param';

describe('Credential security check: credential password forbid reuse', () => {
    const vault = getBaseVault();
    const rule = credentialPasswordComplexityForbidReuse();
    const rulebook = new Rulebook<credentialRuleParameters>();
    rulebook.add(rule);

    after(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidReuse = false;
    });

    it('throws when the password is reused', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidReuse = true;
        // The vault contains a credential with password 'lorum-ipsum'
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            `Credential password is used by another credential: 'Root/lorum'`
        );
    });

    it('does not throw when the config is false', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidReuse = false;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the password is unique', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidReuse = true;
        params.credential.data.password = new SecretValue('string', 'orum-ipsum');

        await rulebook.enforce(rule.name, params);
    });
});
