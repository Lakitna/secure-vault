import { expect } from 'chai';
import Rulebook from 'rulebound';
import { SecretValue } from '../../../../../src';
import { vaultRuleParameters } from '../../../../../src/security-checker';
import { vaultPasswordLength } from '../../../../../src/security-checker/vault/password/length';
import { getBaseVault } from '../../../support/base-vault';
import { vaultRuleParams } from '../../../support/vault-rule-param';

describe('Vault security check: vault password length', () => {
    const vault = getBaseVault();
    const rule = vaultPasswordLength();
    const rulebook = new Rulebook<vaultRuleParameters>();
    rulebook.add(rule);

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.minPasswordLength = 1;
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
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.minPasswordLength = 0;

        await rulebook.enforce(rule.name, params);
    });

    it('throws when the config is below 0', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.minPasswordLength = -5;

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Configuration error: Min password length can not be below 0'
        );
    });
});
