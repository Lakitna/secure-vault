import { expect } from 'chai';
import Rulebook from 'rulebound';
import sinon from 'sinon';
import { vaultRuleParameters } from '../../../../src/security-checker';
import { vaultDecryptionTime } from '../../../../src/security-checker/vault/vault-decryption-time';
import { getBaseVault } from '../../support/base-vault';
import { vaultRuleParams } from '../../support/vault-rule-param';

describe('Vault security check: vault decryption time', () => {
    const vault = getBaseVault();
    const rule = vaultDecryptionTime();
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

    it('does not throw when the decryption time is not set in the vault', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.minDecryptionTime = 100;
        params.vault.meta.customData.set('KPXC_DECRYPTION_TIME_PREFERENCE', { value: undefined });

        const consoleErrorStub = sinon.stub(console, 'error');

        await rulebook.enforce(rule.name, params);

        expect(consoleErrorStub).to.have.been.calledOnceWithExactly(
            'Could not fetch decryption time from vault'
        );
    });

    it('throws when the config is below 0', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.minDecryptionTime = -5;

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Configuration error: Min decryption time can not be below 0'
        );
    });
});
