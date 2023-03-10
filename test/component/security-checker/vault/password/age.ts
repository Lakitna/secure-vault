import { expect } from 'chai';
import Rulebook, { Rule } from 'rulebound';
import * as sinon from 'sinon';
import { vaultRuleParameters } from '../../../../../src/security-checker';
import { vaultPasswordAge } from '../../../../../src/security-checker/vault/password/age';
import { getBaseVault } from '../../../support/base-vault';
import { vaultRuleParams } from '../../../support/vault-rule-param';

const hourInMilliseconds = 3600000;

describe('Vault security check: vault password age', () => {
    const vault = getBaseVault();
    const rulebook = new Rulebook<vaultRuleParameters>();
    let rule: Rule<vaultRuleParameters>;

    beforeEach(() => {
        rule = vaultPasswordAge();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.maxPasswordAge = Infinity;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).to.equal(1);

        const rule = rulebook.rules[0];
        expect(rule.description).to.be.a('string');
        expect(rule.description?.length).to.be.above(0);
    });

    it('throws when the credential password is too old', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.maxPasswordAge = 10;
        params.vault.meta.keyChanged = new Date(new Date().getTime() - 15 * hourInMilliseconds);

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Vault password is too old, change it'
        );
    });

    it('does not throw when the credential password not too old', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.maxPasswordAge = 10;
        params.vault.meta.keyChanged = new Date(new Date().getTime() - 5 * hourInMilliseconds);

        await rulebook.enforce(rule.name, params);
    });

    it('disables when the config is 0', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = sinon.stub(rule._log, 'error');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.maxPasswordAge = 0;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogErrorStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Configuration error: Max password age can not be equal to or below 0'
        );
    });

    it('disables when the config is below 0', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = sinon.stub(rule._log, 'error');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.maxPasswordAge = -5;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogErrorStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Configuration error: Max password age can not be equal to or below 0'
        );
    });

    it('disables when the config is Infinity', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.maxPasswordAge = Infinity;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Disabled by security config `maxPasswordAge`'
        );
    });

    it('throws when the password age cant be found', async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.maxPasswordAge = 5;
        params.vault.meta.keyChanged = undefined;

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Could not find when the vault password was last changed. Assuming the worst.'
        );
    });
});
