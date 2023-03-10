import { expect } from 'chai';
import Rulebook, { Rule } from 'rulebound';
import * as sinon from 'sinon';
import { SecretValue } from '../../../../../src';
import { credentialRuleParameters } from '../../../../../src/security-checker';
import { credentialPasswordLength } from '../../../../../src/security-checker/credential/password/length';
import { getBaseVault } from '../../../support/base-vault';
import { credentialRuleParam } from '../../../support/credential-rule-param';

describe('Credential security check: credential password length', () => {
    const vault = getBaseVault();
    const rulebook = new Rulebook<credentialRuleParameters>();
    let rule: Rule<credentialRuleParameters>;

    beforeEach(() => {
        rule = credentialPasswordLength();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    after(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.minPasswordLength = 1;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).to.equal(1);

        const rule = rulebook.rules[0];
        expect(rule.description).to.be.a('string');
        expect(rule.description?.length).to.be.above(0);
    });

    it('throws when the credential password is too short', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.minPasswordLength = 10;
        params.credential.data.password = new SecretValue('string', 'short');

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Credential password too short. Should be at least 10 characters.'
        );
    });

    it('does not throw when the credential password is the exact min lenght', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.minPasswordLength = 10;
        params.credential.data.password = new SecretValue('string', '0123456789');

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the credential password is longer than minimum', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.minPasswordLength = 3;
        params.credential.data.password = new SecretValue('string', '0123456789');

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the config is 0', async () => {
        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = sinon.stub(rule._log, 'error');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.minPasswordLength = 0;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogErrorStub).to.not.have.been.called;
    });

    it('disables when the config is below 0', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = sinon.stub(rule._log, 'error');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.minPasswordLength = -5;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogErrorStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Configuration error: Min password length can not be below 0'
        );
    });
});
