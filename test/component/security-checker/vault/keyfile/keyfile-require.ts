import { expect } from 'chai';
import Rulebook from 'rulebound';
import { vaultRuleParameters } from '../../../../../src/security-checker';
import { vaultKeyfileRequire } from '../../../../../src/security-checker/vault/keyfile/keyfile-require';
import { getBaseVault } from '../../../support/base-vault';
import { vaultRuleParams } from '../../../support/vault-rule-param';

describe('Vault security check: require keyfile', () => {
    const vault = getBaseVault();
    const rule = vaultKeyfileRequire();
    const rulebook = new Rulebook<vaultRuleParameters>();
    rulebook.add(rule);

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.requireKeyfile = false;
    });

    it('throws when there is no keyfile', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.requireKeyfile = true;
        params.vaultCredential.keyfilePath = undefined;

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Vault requires keyfile as second authentication factor'
        );
    });

    it('does not throw when there is a keyfile', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.requireKeyfile = true;
        params.vaultCredential.keyfilePath = 'path/to/keyfile';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when a keyfile is not required', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.requireKeyfile = false;
        params.vaultCredential.keyfilePath = undefined;

        await rulebook.enforce(rule.name, params);
    });
});
