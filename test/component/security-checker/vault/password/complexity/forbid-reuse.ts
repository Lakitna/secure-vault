import { expect } from 'chai';
import Rulebook from 'rulebound';
import { SecretValue } from '../../../../../../src';
import { vaultRuleParameters } from '../../../../../../src/security-checker';
import { vaultPasswordComplexityCharacterForbidReuse } from '../../../../../../src/security-checker/vault/password/complexity/forbid-reuse';
import { getBaseVault } from '../../../../support/base-vault';
import { vaultRuleParams } from '../../../../support/vault-rule-param';

describe('Vault security check: vault password forbid reuse', () => {
    const vault = getBaseVault();
    const rule = vaultPasswordComplexityCharacterForbidReuse();
    const rulebook = new Rulebook<vaultRuleParameters>();
    rulebook.add(rule);

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.passwordComplexity.forbidReuse = false;
    });

    it('throws when the password is also used by a credential', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidReuse = true;
        // The vault contains a credential with password 'lorum-ipsum'
        params.vaultCredential.password = new SecretValue('string', 'lorum-ipsum');

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            `Vault password is used by a credential: 'Root/lorum'`
        );
    });

    it('does not throw when the config is false', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidReuse = false;
        params.vaultCredential.password = new SecretValue('string', 'lorum-ipsum');

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the password is unique', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidReuse = true;
        // The vault contains a credential with password 'lorum-ipsum'
        params.vaultCredential.password = new SecretValue('string', 'orum-ipsum');

        await rulebook.enforce(rule.name, params);
    });
});
