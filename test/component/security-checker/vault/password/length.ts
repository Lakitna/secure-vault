import { expect } from 'chai';
import Rulebook, { Rule } from 'rulebound';
import * as sinon from 'sinon';
import { SecretValue } from '../../../../../src';
import { vaultRuleParameters } from '../../../../../src/security-checker';
import { vaultPasswordLength } from '../../../../../src/security-checker/vault/password/length';
import { getBaseVault } from '../../../support/base-vault';
import { vaultRuleParams } from '../../../support/vault-rule-param';

describe('Vault security check: vault password length', () => {
    const vault = getBaseVault();
    const rulebook = new Rulebook<vaultRuleParameters>();
    let rule: Rule<vaultRuleParameters>;

    beforeEach(() => {
        rule = vaultPasswordLength();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.minPasswordLength = 1;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).to.equal(1);

        const rule = rulebook.rules[0];
        expect(rule.description).to.be.a('string');
        expect(rule.description?.length).to.be.above(0);
    });

    it('throws when the vault password is too short', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.minPasswordLength = 10;
        params.vaultCredential.password = new SecretValue('string', 'short');

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Vault password too short. Should be at least 10 characters.'
        );
    });

    it('does not throw when the vault password is the exact min lenght', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.minPasswordLength = 10;
        params.vaultCredential.password = new SecretValue('string', '0123456789');

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the vault password is longer than minimum', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.minPasswordLength = 3;
        params.vaultCredential.password = new SecretValue('string', '0123456789');

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the config is 0', async () => {
        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = sinon.stub(rule._log, 'error');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.minPasswordLength = 0;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogErrorStub).to.not.have.been.called;
    });

    it('disables when the config is below 0', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = sinon.stub(rule._log, 'error');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.minPasswordLength = -5;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogErrorStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Configuration error: Min password length can not be below 0'
        );
    });
});
