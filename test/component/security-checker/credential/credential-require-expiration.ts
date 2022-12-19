import { expect } from 'chai';
import Rulebook from 'rulebound';
import { credentialRuleParameters } from '../../../../src/security-checker';
import { credentialRequireExpiration } from '../../../../src/security-checker/credential/credential-require-expiration';
import { getBaseVault } from '../../support/base-vault';
import { credentialRuleParam } from '../../support/credential-rule-param';

describe('Credential security check: credential require expiration', () => {
    const vault = getBaseVault();
    const rule = credentialRequireExpiration();
    const rulebook = new Rulebook<credentialRuleParameters>();
    rulebook.add(rule);

    after(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.requireExpiration = false;
    });

    it('throws when the credential has no expiration date', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.requireExpiration = true;
        params.credential.hasExpiration = false;

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Credential has no exipiration date'
        );
    });

    it('does not throw when the credential has expiration date', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.requireExpiration = true;
        params.credential.hasExpiration = true;

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the no expiration date is required', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.requireExpiration = false;
        params.credential.hasExpiration = false;

        await rulebook.enforce(rule.name, params);
    });
});
