import { expect } from 'chai';
import Rulebook from 'rulebound';
import sinon from 'sinon';
import { vaultRuleParameters } from '../../../../src/security-checker';
import { keepassVaultDecryptionTime } from '../../../../src/security-checker/vault/keepass/vault-decryption-time';
import { getBaseVault } from '../../support/base-vault';
import { vaultRuleParams } from '../../support/vault-rule-param';

describe('Vault security check: vault decryption time', () => {
    const vault = getBaseVault();
    const rule = keepassVaultDecryptionTime();
    const rulebook = new Rulebook<vaultRuleParameters>();
    rulebook.add(rule);

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.minDecryptionTime = 0;
    });

    it('throws when the decryption time is too short', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.minDecryptionTime = 100;
        params.vault.meta.customData.set('KPXC_DECRYPTION_TIME_PREFERENCE', { value: '50' });

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Vault decryption time is too short. Should be at least 100ms.'
        );
    });

    it('does not throw when the decryption time is the exact min lenght', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.minDecryptionTime = 100;
        params.vault.meta.customData.set('KPXC_DECRYPTION_TIME_PREFERENCE', { value: '100' });

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the decryption time is longer than minimum', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.minDecryptionTime = 100;
        params.vault.meta.customData.set('KPXC_DECRYPTION_TIME_PREFERENCE', { value: '1000' });

        await rulebook.enforce(rule.name, params);
    });

    it('disables when the decryption time is not set in the vault', async () => {
        const rule = keepassVaultDecryptionTime();
        const rulebook = new Rulebook<vaultRuleParameters>();
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });
        rulebook.add(rule);

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.minDecryptionTime = 100;
        params.vault.meta.customData.set('KPXC_DECRYPTION_TIME_PREFERENCE', { value: undefined });

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Could not fetch decryption time from vault'
        );
    });

    it('disables when the config is below 0', async () => {
        const rule = keepassVaultDecryptionTime();
        const rulebook = new Rulebook<vaultRuleParameters>();
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });
        rulebook.add(rule);

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = sinon.stub(rule._log, 'error');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.minDecryptionTime = -5;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogErrorStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Configuration error: Min decryption time can not be below 0'
        );
    });
});
