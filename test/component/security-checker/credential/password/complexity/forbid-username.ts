import { expect } from 'chai';
import Rulebook from 'rulebound';
import { SecretValue } from '../../../../../../src';
import { credentialRuleParameters } from '../../../../../../src/security-checker';
import { credentialPasswordComplexityForbidUsername } from '../../../../../../src/security-checker/credential/password/complexity/forbid-username';
import { getBaseVault } from '../../../../support/base-vault';
import { credentialRuleParam } from '../../../../support/credential-rule-param';

describe('Credential security check: credential password forbid username', () => {
    const vault = getBaseVault();
    const rule = credentialPasswordComplexityForbidUsername();
    const rulebook = new Rulebook<credentialRuleParameters>();
    rulebook.add(rule);

    after(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUsername = false;
    });

    it('throws when the username contains the password', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUsername = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.username = 'lorum';

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            `Password contains (part of) username`
        );
    });

    it('throws when the username email contains the password', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUsername = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.username =
            'lorum@a-very-long-domain-name-that-may-cause-matching-to-be-difficult.com';

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            `Password contains (part of) username`
        );
    });

    it('does not throw when the config is false', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUsername = false;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.username = 'lorum';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the password is different from the username', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUsername = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.username = 'something-else';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when there is no username', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUsername = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.username = '';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when there is no password', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUsername = true;
        params.credential.data.password = new SecretValue('string', '');
        params.credential.data.username = 'my-username';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the username email domain matches', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUsername = true;
        params.credential.data.password = new SecretValue('string', 'gmail');
        params.credential.data.username = 'my-username@gmail.com';

        await rulebook.enforce(rule.name, params);
    });
});
