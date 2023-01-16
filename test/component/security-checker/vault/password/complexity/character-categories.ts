import { expect } from 'chai';
import Rulebook from 'rulebound';
import * as sinon from 'sinon';
import { SecretValue } from '../../../../../../src';
import { vaultRuleParameters } from '../../../../../../src/security-checker';
import { vaultPasswordComplexityCharacterCategories } from '../../../../../../src/security-checker/vault/password/complexity/character-categories';
import { getBaseVault } from '../../../../support/base-vault';
import { vaultRuleParams } from '../../../../support/vault-rule-param';

describe('Vault security check: vault password character categories', () => {
    const vault = getBaseVault();
    const rule = vaultPasswordComplexityCharacterCategories();
    const rulebook = new Rulebook<vaultRuleParameters>();
    rulebook.add(rule);

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.passwordComplexity.minCharacterCategories = 1;
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

        params.config.vaultRestrictions.passwordComplexity.minCharacterCategories = 1;
        params.vaultCredential.password = new SecretValue('string', '');

        await rulebook.enforce(rule.name, params);
    });

    it('disables when the config is 0', async () => {
        const rule = vaultPasswordComplexityCharacterCategories();
        const rulebook = new Rulebook<vaultRuleParameters>();
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });
        rulebook.add(rule);

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
        const rule = vaultPasswordComplexityCharacterCategories();
        const rulebook = new Rulebook<vaultRuleParameters>();
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });
        rulebook.add(rule);

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
