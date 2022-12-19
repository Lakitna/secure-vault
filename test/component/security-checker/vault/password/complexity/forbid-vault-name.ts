import { expect } from 'chai';
import Rulebook from 'rulebound';
import { SecretValue } from '../../../../../../src';
import { vaultRuleParameters } from '../../../../../../src/security-checker';
import { vaultPasswordComplexityCharacterForbidVaultName } from '../../../../../../src/security-checker/vault/password/complexity/forbid-vault-name';
import { getBaseVault } from '../../../../support/base-vault';
import { vaultRuleParams } from '../../../../support/vault-rule-param';

describe('Vault security check: vault password forbid vault name', () => {
    const vault = getBaseVault();
    const rule = vaultPasswordComplexityCharacterForbidVaultName();
    const rulebook = new Rulebook<vaultRuleParameters>();
    rulebook.add(rule);

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.passwordComplexity.forbidVaultName = false;
    });

    it('throws when the vault name contains the password', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidVaultName = true;
        params.vaultCredential.password = new SecretValue('string', 'lorsum');
        params.vault.meta.name = 'lorum-ipsum';

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            `Vault password contains (part of) the vault name`
        );
    });

    it('does not throw when the config is false', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidVaultName = false;
        params.vaultCredential.password = new SecretValue('string', 'lorum');
        params.vault.meta.name = 'lorum-ipsum';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the password is different from the vault name', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidVaultName = true;
        params.vaultCredential.password = new SecretValue('string', 'some-other-password');
        params.vault.meta.name = 'lorum-ipsum';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when there is no password', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidVaultName = true;
        params.vaultCredential.password = new SecretValue('string', '');
        params.vault.meta.name = 'lorum-ipsum';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when there is no vault name', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidVaultName = true;
        params.vaultCredential.password = new SecretValue('string', 'lorum');
        params.vault.meta.name = '';

        await rulebook.enforce(rule.name, params);
    });
});
