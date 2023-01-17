import { expect } from 'chai';
import Rulebook, { Rule } from 'rulebound';
import * as sinon from 'sinon';
import { SecretValue } from '../../../../../../src';
import { vaultRuleParameters } from '../../../../../../src/security-checker';
import { vaultPasswordComplexityCharacterCategories } from '../../../../../../src/security-checker/vault/password/complexity/character-categories';
import { getBaseVault } from '../../../../support/base-vault';
import { vaultRuleParams } from '../../../../support/vault-rule-param';

describe('Vault security check: vault password character categories', () => {
    const vault = getBaseVault();
    const rulebook = new Rulebook<vaultRuleParameters>();
    let rule: Rule<vaultRuleParameters>;

    beforeEach(() => {
        rule = vaultPasswordComplexityCharacterCategories();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.passwordComplexity.minCharacterCategories = 1;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).to.equal(1);

        const rule = rulebook.rules[0];
        expect(rule.description).to.be.a('string');
        expect(rule.description?.length).to.be.above(0);
    });

    it('throws when the password uses too few categories', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.minCharacterCategories = 3;
        params.vaultCredential.password = new SecretValue('string', 'abc123');

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Vault password not complex enough. ' +
                'Should contain at least 3 characters categories but only contains 2.'
        );
    });

    it('does not throw when the password uses the same amount of categories', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.minCharacterCategories = 2;
        params.vaultCredential.password = new SecretValue('string', 'abc123');

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the password uses the more categories', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.minCharacterCategories = 2;
        params.vaultCredential.password = new SecretValue('string', 'abc123ABC');

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the config is 1', async () => {
        const params = await vaultRuleParams(vault);

        // @ts-expect-error Accessing a private var
        const disableLogErrorStub = sinon.stub(rule._log, 'error');

        params.config.vaultRestrictions.passwordComplexity.minCharacterCategories = 1;
        params.vaultCredential.password = new SecretValue('string', '');

        await rulebook.enforce(rule.name, params);

        expect(disableLogErrorStub).to.have.not.been.called;
    });

    it('enforces and does not throw when the config is 4', async () => {
        const params = await vaultRuleParams(vault);

        // @ts-expect-error Accessing a private var
        const disabledLogErrorStub = sinon.stub(rule._log, 'error');

        params.config.vaultRestrictions.passwordComplexity.minCharacterCategories = 4;
        params.vaultCredential.password = new SecretValue('string', 'abc123ABC!@#');

        await rulebook.enforce(rule.name, params);

        expect(disabledLogErrorStub).to.have.not.been.called;
    });

    it('disables when the config is 0', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = sinon.stub(rule._log, 'error');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.passwordComplexity.minCharacterCategories = 0;

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

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.passwordComplexity.minCharacterCategories = 5;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogErrorStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Configuration error: Min character category count can not be above 4'
        );
    });
});
