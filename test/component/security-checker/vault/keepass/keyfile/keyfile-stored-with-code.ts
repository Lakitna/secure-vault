import { expect } from 'chai';
import Rulebook, { Rule } from 'rulebound';
import sinon from 'sinon';
import { vaultRuleParameters } from '../../../../../../src/security-checker';
import { keepassVaultKeyfileStoredWithCode } from '../../../../../../src/security-checker/vault/keepass/keyfile/keyfile-stored-with-code';
import file from '../../../../../../src/util/file-with-code';
import { getBaseVault } from '../../../../support/base-vault';
import { vaultRuleParams } from '../../../../support/vault-rule-param';

describe('Vault security check: keyfile stored with code', () => {
    const vault = getBaseVault();
    const rulebook = new Rulebook<vaultRuleParameters>();
    let rule: Rule<vaultRuleParameters>;

    beforeEach(() => {
        rule = keepassVaultKeyfileStoredWithCode();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.allowKeyfileWithCode = true;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).to.equal(1);

        const rule = rulebook.rules[0];
        expect(rule.description).to.be.a('string');
        expect(rule.description?.length).to.be.above(0);
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

    it('disables when storing with code is allowed', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.allowKeyfileWithCode = true;
        const stub = sinon.stub(file, 'fileWithCode').resolves(true);
        params.vaultCredential.keyfilePath = 'path/to/keyfile';

        await rulebook.enforce(rule.name, params);
        expect(stub).to.not.have.been.called;

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Disabled by security config `allowKeyfileWithCode`'
        );
    });

    it('disables when there is no keyfile', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.allowKeyfileWithCode = false;
        const stub = sinon.stub(file, 'fileWithCode').resolves(true);
        params.vaultCredential.keyfilePath = undefined;

        await rulebook.enforce(rule.name, params);
        expect(stub).to.not.have.been.called;

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: No keyfile defined'
        );
    });
});
