import { expect } from 'chai';
import Rulebook, { Rule } from 'rulebound';
import sinon from 'sinon';
import { vaultRuleParameters } from '../../../../../src/security-checker';
import { keepassVaultStoredWithCode } from '../../../../../src/security-checker/vault/keepass/vault-stored-with-code';
import file from '../../../../../src/util/file-with-code';
import { getBaseVault } from '../../../support/base-vault';
import { vaultRuleParams } from '../../../support/vault-rule-param';

describe('Vault security check: vault stored with code', () => {
    const vault = getBaseVault();
    const rulebook = new Rulebook<vaultRuleParameters>();
    let rule: Rule<vaultRuleParameters>;

    beforeEach(() => {
        rule = keepassVaultStoredWithCode();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.allowVaultWithCode = true;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).to.equal(1);

        const rule = rulebook.rules[0];
        expect(rule.description).to.be.a('string');
        expect(rule.description?.length).to.be.above(0);
    });

    it('throws when the vault is stored with code', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.allowVaultWithCode = false;
        const stub = sinon.stub(file, 'fileWithCode').resolves(true);

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Vault is stored with source code'
        );
        expect(stub).to.have.been.called;
    });

    it('does not throw when the vault is not stored with code', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.allowVaultWithCode = false;
        const stub = sinon.stub(file, 'fileWithCode').resolves(false);

        await rulebook.enforce(rule.name, params);
        expect(stub).to.have.been.called;
    });

    it('disables when storing with code is allowed', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.allowVaultWithCode = true;
        const stub = sinon.stub(file, 'fileWithCode').resolves(true);

        await rulebook.enforce(rule.name, params);

        expect(stub).to.not.have.been.called;
        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Disabled by security config `allowVaultWithCode`'
        );
    });
});
