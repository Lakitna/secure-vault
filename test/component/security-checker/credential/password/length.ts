import { expect } from 'chai';
import Rulebook from 'rulebound';
import { SecretValue } from '../../../../../src';
import { credentialRuleParameters } from '../../../../../src/security-checker';
import { credentialPasswordLength } from '../../../../../src/security-checker/credential/password/length';
import { getBaseVault } from '../../../support/base-vault';
import { credentialRuleParam } from '../../../support/credential-rule-param';

describe('Credential security check: credential password length', () => {
    const vault = getBaseVault();
    const rule = credentialPasswordLength();
    const rulebook = new Rulebook<credentialRuleParameters>();
    rulebook.add(rule);

    after(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.minPasswordLength = 1;
    });

    it('throws when the credential password is too short', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.minPasswordLength = 10;
        params.credential.data.password = new SecretValue('string', 'short');

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Credential password too short. Should be at least 10 characters.'
        );
    });

    it('does not throw when the credential password is the exact min lenght', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.minPasswordLength = 10;
        params.credential.data.password = new SecretValue('string', '0123456789');

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the credential password is longer than minimum', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.minPasswordLength = 3;
        params.credential.data.password = new SecretValue('string', '0123456789');

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the config is 0', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.minPasswordLength = 0;

        await rulebook.enforce(rule.name, params);
    });

    it('throws when the config is below 0', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.minPasswordLength = -5;

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Configuration error: Min password length can not be below 0'
        );
    });
});
