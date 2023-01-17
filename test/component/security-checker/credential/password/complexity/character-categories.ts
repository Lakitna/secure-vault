import { expect } from 'chai';
import Rulebook, { Rule } from 'rulebound';
import * as sinon from 'sinon';
import { SecretValue } from '../../../../../../src';
import { credentialRuleParameters } from '../../../../../../src/security-checker';
import { credentialPasswordComplexityCharacterCategories } from '../../../../../../src/security-checker/credential/password/complexity/character-categories';
import { getBaseVault } from '../../../../support/base-vault';
import { credentialRuleParam } from '../../../../support/credential-rule-param';

describe('Credential security check: credential password character categories', () => {
    const vault = getBaseVault();
    const rulebook = new Rulebook<credentialRuleParameters>();
    let rule: Rule<credentialRuleParameters>;

    beforeEach(() => {
        rule = credentialPasswordComplexityCharacterCategories();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    after(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.minCharacterCategories = 1;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).to.equal(1);

        const rule = rulebook.rules[0];
        expect(rule.description).to.be.a('string');
        expect(rule.description?.length).to.be.above(0);
    });

    it('throws when the password uses too few categories', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.minCharacterCategories = 3;
        params.credential.data.password = new SecretValue('string', 'abc123');

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Credential password not complex enough. ' +
                'Should contain at least 3 characters categories but only contains 2.'
        );
    });

    it('does not throw when the password uses the same amount of categories', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.minCharacterCategories = 2;
        params.credential.data.password = new SecretValue('string', 'abc123');

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the password uses the more categories', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.minCharacterCategories = 2;
        params.credential.data.password = new SecretValue('string', 'abc123ABC');

        await rulebook.enforce(rule.name, params);
    });

    it('enforces and does not throw when the config is 1', async () => {
        const params = await credentialRuleParam(vault);

        // @ts-expect-error Accessing a private var
        const disabledLogErrorStub = sinon.stub(rule._log, 'error');

        params.config.credentialRestrictions.passwordComplexity.minCharacterCategories = 1;
        params.credential.data.password = new SecretValue('string', '');

        await rulebook.enforce(rule.name, params);

        expect(disabledLogErrorStub).to.have.not.been.called;
    });

    it('enforces and does not throw when the config is 4', async () => {
        const params = await credentialRuleParam(vault);

        // @ts-expect-error Accessing a private var
        const disabledLogErrorStub = sinon.stub(rule._log, 'error');

        params.config.credentialRestrictions.passwordComplexity.minCharacterCategories = 4;
        params.credential.data.password = new SecretValue('string', 'abc123ABC!@#');

        await rulebook.enforce(rule.name, params);

        expect(disabledLogErrorStub).to.have.not.been.called;
    });

    it('disables when the config is 0', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = sinon.stub(rule._log, 'error');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.minCharacterCategories = 0;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogErrorStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Configuration error: Min character category count can not be below 1'
        );
    });

    it('disables when the config is too high', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = sinon.stub(rule._log, 'error');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.minCharacterCategories = 5;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogErrorStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Configuration error: Min character category count can not be above 4'
        );
    });
});
