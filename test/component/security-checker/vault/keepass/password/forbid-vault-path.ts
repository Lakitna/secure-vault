import { expect } from 'chai';
import Rulebook, { Rule } from 'rulebound';
import * as sinon from 'sinon';
import { SecretValue } from '../../../../../../src';
import { vaultRuleParameters } from '../../../../../../src/security-checker';
import { keepassVaultPasswordComplexityCharacterForbidVaultPath } from '../../../../../../src/security-checker/vault/keepass/password/forbid-vault-path';
import { getBaseVault } from '../../../../support/base-vault';
import { vaultRuleParams } from '../../../../support/vault-rule-param';

describe('Vault security check: vault password forbid vault path', () => {
    const vault = getBaseVault();
    const rulebook = new Rulebook<vaultRuleParameters>();
    let rule: Rule<vaultRuleParameters>;

    beforeEach(() => {
        rule = keepassVaultPasswordComplexityCharacterForbidVaultPath();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.passwordComplexity.forbidVaultPath = false;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).to.equal(1);

        const rule = rulebook.rules[0];
        expect(rule.description).to.be.a('string');
        expect(rule.description?.length).to.be.above(0);
    });

    it('throws when the vault path contains the password', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidVaultPath = true;
        params.vaultCredential.password = new SecretValue('string', 'lorum-ipsum');
        params.vaultPaths.vault = '/some/file/path/lorum/ipsum.kdbx';

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            `Vault password contains (part of) the vault file path`
        );
    });

    it('disables when the config is false', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.passwordComplexity.forbidVaultPath = false;
        params.vaultCredential.password = new SecretValue('string', 'lorum-ipsum');
        params.vaultPaths.vault = '/some/file/path/lorum/ipsum.kdbx';

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Disabled by security config `forbidVaultPath`'
        );
    });

    it('does not throw when the password is different from the vault path', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidVaultPath = true;
        params.vaultCredential.password = new SecretValue('string', 'lorum-ipsum');
        params.vaultPaths.vault = '/some/file/path/vault.kdbx';

        await rulebook.enforce(rule.name, params);
    });

    it('disables when there is no password', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.passwordComplexity.forbidVaultPath = true;
        params.vaultCredential.password = new SecretValue('string', '');
        params.vaultPaths.vault = '/some/file/path/vault.kdbx';

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: No vault password, nothing to check'
        );
    });
});
