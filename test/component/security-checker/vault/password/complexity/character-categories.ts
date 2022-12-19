import { expect } from 'chai';
import Rulebook from 'rulebound';
import { SecretValue } from '../../../../../../src';
import { vaultRuleParameters } from '../../../../../../src/security-checker';
import { vaultPasswordComplexityCharacterCategories } from '../../../../../../src/security-checker/vault/password/complexity/character-categories';
import { getBaseVault } from '../../../../support/base-vault';
import { vaultRuleParams } from '../../../../support/vault-rule-param';

describe('Vault security check: vault password character categories', () => {
    const vault = getBaseVault();
    const rule = vaultPasswordComplexityCharacterCategories();
    const rulebook = new Rulebook<vaultRuleParameters>();
    rulebook.add(rule);

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.passwordComplexity.minCharacterCategories = 1;
    });

    it('throws when the password uses too few categories', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.minCharacterCategories = 3;
        params.vaultCredential.password = new SecretValue('string', 'abc123');

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Vault password not complex enough. ' +
                'Should contain at least 3 characters categories but only contains 2.'
        );
    });

    it('does not throw when the password uses the same amount of categories', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.minCharacterCategories = 2;
        params.vaultCredential.password = new SecretValue('string', 'abc123');

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the password uses the more categories', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.minCharacterCategories = 2;
        params.vaultCredential.password = new SecretValue('string', 'abc123ABC');

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the config is 1', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.minCharacterCategories = 1;
        params.vaultCredential.password = new SecretValue('string', '');

        await rulebook.enforce(rule.name, params);
    });

    it('throws when the config is 0', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.minCharacterCategories = 0;

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Configuration error: Min character category count can not be below 1'
        );
    });

    it('throws when the config is too high', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.minCharacterCategories = 5;

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Configuration error: Min character category count can not be above 4'
        );
    });
});
