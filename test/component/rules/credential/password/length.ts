import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { credentialPasswordLength } from '../../../../../src/rules/credential/password/length.ts';
import { SecretValue } from '../../../../../src/secret-value.ts';
import { CredentialRuleParameters } from '../../../../../src/vault/enforcable.ts';
import { getBaseVault } from '../../../support/base-vault.ts';
import { credentialRuleParam } from '../../../support/credential-rule-param.ts';

describe('Credential security check: credential password length', async () => {
    const vault = await getBaseVault();
    const rulebook = new Rulebook<CredentialRuleParameters>();
    let rule: Rule<CredentialRuleParameters>;

    beforeEach(() => {
        rule = credentialPasswordLength();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.minPasswordLength = 1;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('throws when the credential password is too short', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.minPasswordLength = 10;
        params.credential.data.password = new SecretValue('string', 'short');

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
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
        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = vi.spyOn(rule._log, 'error');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.minPasswordLength = 0;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogErrorStub).toHaveBeenCalledTimes(0);
    });

    it('disables when the config is below 0', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = vi.spyOn(rule._log, 'error');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.minPasswordLength = -5;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogErrorStub).toHaveBeenCalledWith(
            'Rule disabled: Configuration error: Min password length can not be below 0'
        );
    });
});
