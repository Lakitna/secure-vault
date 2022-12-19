import { expect } from 'chai';
import Rulebook from 'rulebound';
import { SecretValue } from '../../../../../../src';
import { vaultRuleParameters } from '../../../../../../src/security-checker';
import { vaultPasswordComplexityCharacterForbidVaultPath } from '../../../../../../src/security-checker/vault/password/complexity/forbid-vault-path';
import { getBaseVault } from '../../../../support/base-vault';
import { vaultRuleParams } from '../../../../support/vault-rule-param';

describe('Vault security check: vault password forbid vault path', () => {
    const vault = getBaseVault();
    const rule = vaultPasswordComplexityCharacterForbidVaultPath();
    const rulebook = new Rulebook<vaultRuleParameters>();
    rulebook.add(rule);

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.passwordComplexity.forbidVaultPath = false;
    });

    it('throws when the vault path contains the password', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidVaultPath = true;
        params.vaultCredential.password = new SecretValue('string', 'lorum-ipsum');
        params.vaultCredential.path = '/some/file/path/lorum/ipsum.kdbx';

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            `Vault password contains (part of) the vault file path`
        );
    });

    it('does not throw when the config is false', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidVaultPath = false;
        params.vaultCredential.password = new SecretValue('string', 'lorum-ipsum');
        params.vaultCredential.path = '/some/file/path/lorum/ipsum.kdbx';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the password is different from the vault path', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidVaultPath = true;
        params.vaultCredential.password = new SecretValue('string', 'lorum-ipsum');
        params.vaultCredential.path = '/some/file/path/vault.kdbx';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when there is no password', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidVaultPath = true;
        params.vaultCredential.password = new SecretValue('string', '');
        params.vaultCredential.path = '/some/file/path/vault.kdbx';

        await rulebook.enforce(rule.name, params);
    });
});
