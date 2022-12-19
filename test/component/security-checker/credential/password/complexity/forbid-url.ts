import { expect } from 'chai';
import Rulebook from 'rulebound';
import { SecretValue } from '../../../../../../src';
import { credentialRuleParameters } from '../../../../../../src/security-checker';
import { credentialPasswordComplexityForbidUrl } from '../../../../../../src/security-checker/credential/password/complexity/forbid-url';
import { getBaseVault } from '../../../../support/base-vault';
import { credentialRuleParam } from '../../../../support/credential-rule-param';

describe('Credential security check: credential password forbid url', () => {
    const vault = getBaseVault();
    const rule = credentialPasswordComplexityForbidUrl();
    const rulebook = new Rulebook<credentialRuleParameters>();
    rulebook.add(rule);

    after(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUrl = false;
    });

    it('throws when the url contains the password', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.url = 'https://lorum.ipsum.org';

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            `Password contains (part of) URL domain`
        );
    });

    it('does not throw when the config is false', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUrl = false;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.url = 'https://lorum.ipsum.org';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the password is different from the url', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.url = 'https://google.com';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the matching bit is in the url path', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.url = 'https://google.com/lorum/ipsum/dolor';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the matching bit is in the url query string parameters', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.url = 'https://google.com?lorum=ipsum';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the matching bit is in the url fragment', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.url = 'https://google.com#lorum-ipsum';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when there is no url', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.url = '';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when there is no password', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', '');
        params.credential.data.url = 'https://google.com';

        await rulebook.enforce(rule.name, params);
    });
});
