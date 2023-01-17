import { expect } from 'chai';
import Rulebook, { Rule } from 'rulebound';
import * as sinon from 'sinon';
import { SecretValue } from '../../../../../../src';
import { vaultRuleParameters } from '../../../../../../src/security-checker';
import { vaultPasswordComplexityCharacterForbidReuse } from '../../../../../../src/security-checker/vault/password/complexity/forbid-reuse';
import { getBaseVault } from '../../../../support/base-vault';
import { vaultRuleParams } from '../../../../support/vault-rule-param';

describe('Vault security check: vault password forbid reuse', () => {
    const vault = getBaseVault();
    const rulebook = new Rulebook<vaultRuleParameters>();
    let rule: Rule<vaultRuleParameters>;

    beforeEach(() => {
        rule = vaultPasswordComplexityCharacterForbidReuse();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.passwordComplexity.forbidReuse = false;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).to.equal(1);

        const rule = rulebook.rules[0];
        expect(rule.description).to.be.a('string');
        expect(rule.description?.length).to.be.above(0);
    });

    it('throws when the password is also used by a credential', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidReuse = true;
        // The vault contains a credential with password 'lorum-ipsum'
        params.vaultCredential.password = new SecretValue('string', 'lorum-ipsum');

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            `Vault password is used by a credential: 'Root/lorum'`
        );
    });

    it('disables when the config is false', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidReuse = false;
        params.vaultCredential.password = new SecretValue('string', 'lorum-ipsum');

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Disabled by security config `forbidReuse`'
        );
    });

    it('disables when the vault has no password', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidReuse = true;
        params.vaultCredential.password = new SecretValue('string', '');

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: No vault password'
        );
    });

    it('does not throw when the password is unique', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidReuse = true;
        // The vault contains a credential with password 'lorum-ipsum'
        params.vaultCredential.password = new SecretValue('string', 'orum-ipsum');

        await rulebook.enforce(rule.name, params);
    });
});
