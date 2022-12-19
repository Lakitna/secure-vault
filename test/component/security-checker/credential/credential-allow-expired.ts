import { expect } from 'chai';
import Rulebook from 'rulebound';
import { credentialRuleParameters } from '../../../../src/security-checker';
import { credentialAllowExpired } from '../../../../src/security-checker/credential/credential-allow-expired';
import { getBaseVault } from '../../support/base-vault';
import { credentialRuleParam } from '../../support/credential-rule-param';

describe('Credential security check: allow expired credential', () => {
    const vault = getBaseVault();
    const rule = credentialAllowExpired();
    const rulebook = new Rulebook<credentialRuleParameters>();
    rulebook.add(rule);

    after(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.allowExpired = true;
    });

    it('throws when the credential is expired', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.allowExpired = false;
        params.credential.expired = true;

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith('Credential expired');
    });

    it('does not throw if the credential is not expired', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.allowExpired = false;
        params.credential.expired = false;

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw if expired credentials are allowed', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.allowExpired = true;
        params.credential.expired = true;

        await rulebook.enforce(rule.name, params);
    });
});
