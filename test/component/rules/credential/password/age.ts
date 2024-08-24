import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { credentialPasswordAge } from '../../../../../src/rules/credential/password/age.ts';
import { CredentialRuleParameters } from '../../../../../src/vault/enforcable.ts';
import { getBaseVault } from '../../../support/base-vault.ts';
import { credentialRuleParam } from '../../../support/credential-rule-param.ts';

const vault = await getBaseVault();
const rulebook = new Rulebook<CredentialRuleParameters>();
let rule: Rule<CredentialRuleParameters>;

describe('Credential security check: credential password age', () => {
    beforeEach(() => {
        rule = credentialPasswordAge();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.maxPasswordAge = Infinity;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('throws when the credential password is too old', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.maxPasswordAge = 10;
        params.credential.passwordAge = 20;

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            'Credential password is too old, change it'
        );
    });

    it('does not throw when the credential password not too old', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.maxPasswordAge = 10;
        params.credential.passwordAge = 5;

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
    });

    it('disables when the config is 0', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = vi.spyOn(rule._log, 'error');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.maxPasswordAge = 0;

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();

        expect(ruleLogErrorStub).toHaveBeenCalledWith(
            'Rule disabled: Configuration error: Max password age can not be equal to or below 0'
        );
    });

    it('disables when the config is below 0', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = vi.spyOn(rule._log, 'error');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.maxPasswordAge = -5;

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();

        expect(ruleLogErrorStub).toHaveBeenCalledWith(
            'Rule disabled: Configuration error: Max password age can not be equal to or below 0'
        );
    });
});
