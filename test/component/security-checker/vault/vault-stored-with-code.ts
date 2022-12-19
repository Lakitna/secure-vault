import { expect } from 'chai';
import Rulebook from 'rulebound';
import sinon from 'sinon';
import { vaultRuleParameters } from '../../../../src/security-checker';
import { vaultStoredWithCode } from '../../../../src/security-checker/vault/vault-stored-with-code';
import file from '../../../../src/util/file-with-code';
import { getBaseVault } from '../../support/base-vault';
import { vaultRuleParams } from '../../support/vault-rule-param';

describe('Vault security check: vault stored with code', () => {
    const vault = getBaseVault();
    const rule = vaultStoredWithCode();
    const rulebook = new Rulebook<vaultRuleParameters>();
    rulebook.add(rule);

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.allowVaultWithCode = true;
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

    it('does not throw when storing with code is allowed', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.allowVaultWithCode = true;
        const stub = sinon.stub(file, 'fileWithCode').resolves(true);

        await rulebook.enforce(rule.name, params);
        expect(stub).to.not.have.been.called;
    });
});
