import { expect } from 'chai';
import Rulebook, { Rule } from 'rulebound';
import * as sinon from 'sinon';
import { SecretValue } from '../../../../../../src';
import { credentialRuleParameters } from '../../../../../../src/security-checker';
import { credentialPasswordComplexityForbidUrl } from '../../../../../../src/security-checker/credential/password/complexity/forbid-url';
import { getBaseVault } from '../../../../support/base-vault';
import { credentialRuleParam } from '../../../../support/credential-rule-param';

describe('Credential security check: credential password forbid url', () => {
    const vault = getBaseVault();
    const rulebook = new Rulebook<credentialRuleParameters>();
    let rule: Rule<credentialRuleParameters>;

    beforeEach(() => {
        rule = credentialPasswordComplexityForbidUrl();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    after(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUrl = false;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).to.equal(1);

        const rule = rulebook.rules[0];
        expect(rule.description).to.be.a('string');
        expect(rule.description?.length).to.be.above(0);
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

    it('throws when the password contains the IP URL', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', '127.0.0');
        params.credential.data.url = 'https://127.0.0.1:8000';

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            `Password contains (part of) URL domain`
        );
    });

    it('disables when the config is false', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUrl = false;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Disabled by security config `forbidUrl`'
        );
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

    it('does not throw when the matching bit is a short domain part', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', 'agglcomagglcom');
        params.credential.data.url = 'https://a.ggl.com';

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

    it('disables when there is no url', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.url = '';

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Credential has no URL'
        );
    });

    it('disables when there is no password', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', '');
        params.credential.data.url = 'https://google.com';

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Credential has no password'
        );
    });
});
