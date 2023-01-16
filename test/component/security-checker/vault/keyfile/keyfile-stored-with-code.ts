import { expect } from 'chai';
import Rulebook from 'rulebound';
import sinon from 'sinon';
import { vaultRuleParameters } from '../../../../../src/security-checker';
import { keepassVaultKeyfileStoredWithCode } from '../../../../../src/security-checker/vault/keepass/keyfile/keyfile-stored-with-code';
import file from '../../../../../src/util/file-with-code';
import { getBaseVault } from '../../../support/base-vault';
import { vaultRuleParams } from '../../../support/vault-rule-param';

describe('Vault security check: keyfile stored with code', () => {
    const vault = getBaseVault();
    const rule = keepassVaultKeyfileStoredWithCode();
    const rulebook = new Rulebook<vaultRuleParameters>();
    rulebook.add(rule);

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.allowKeyfileWithCode = true;
    });

    it('throws when the keyfile is stored with code', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.allowKeyfileWithCode = false;
        const stub = sinon.stub(file, 'fileWithCode').resolves(true);
        params.vaultCredential.keyfilePath = 'path/to/keyfile';

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Keyfile is stored with source code'
        );
        expect(stub).to.have.been.called;
    });

    it('does not throw when the keyfile is not stored with code', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.allowKeyfileWithCode = false;
        const stub = sinon.stub(file, 'fileWithCode').resolves(false);
        params.vaultCredential.keyfilePath = 'path/to/keyfile';

        await rulebook.enforce(rule.name, params);
        expect(stub).to.have.been.called;
    });

    it('does not throw when storing with code is allowed', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.allowKeyfileWithCode = true;
        const stub = sinon.stub(file, 'fileWithCode').resolves(true);
        params.vaultCredential.keyfilePath = 'path/to/keyfile';

        await rulebook.enforce(rule.name, params);
        expect(stub).to.not.have.been.called;
    });

    it('does not throw when there is no keyfile', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.allowKeyfileWithCode = false;
        const stub = sinon.stub(file, 'fileWithCode').resolves(true);
        params.vaultCredential.keyfilePath = undefined;

        await rulebook.enforce(rule.name, params);
        expect(stub).to.not.have.been.called;
    });
});
