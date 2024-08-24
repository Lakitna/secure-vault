import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { credentialPasswordComplexityCharacterCategories } from '../../../../../../src/rules/credential/password/complexity/character-categories.ts';
import { SecretValue } from '../../../../../../src/secret-value.ts';
import { CredentialRuleParameters } from '../../../../../../src/vault/enforcable.ts';
import { getBaseVault } from '../../../../support/base-vault.ts';
import { credentialRuleParam } from '../../../../support/credential-rule-param.ts';

const vault = await getBaseVault();
const rulebook = new Rulebook<CredentialRuleParameters>();
let rule: Rule<CredentialRuleParameters>;

describe('Credential security check: credential password character categories', () => {
    beforeEach(() => {
        rule = credentialPasswordComplexityCharacterCategories();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.minCharacterCategories = 1;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('throws when the password uses too few categories', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.minCharacterCategories = 3;
        params.credential.data.password = new SecretValue('string', 'abc123');

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            'Credential password not complex enough. ' +
                'Should contain at least 3 characters categories but only contains 2.'
        );
    });

    it('does not throw when the password uses the same amount of categories', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.minCharacterCategories = 2;
        params.credential.data.password = new SecretValue('string', 'abc123');

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
    });

    it('does not throw when the password uses the more categories', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.minCharacterCategories = 2;
        params.credential.data.password = new SecretValue('string', 'abc123ABC');

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
    });

    it('enforces and does not throw when the config is 1', async () => {
        const params = await credentialRuleParam(vault);

        // @ts-expect-error Accessing a private var
        const disabledLogErrorStub = vi.spyOn(rule._log, 'error');

        params.config.credentialRestrictions.passwordComplexity.minCharacterCategories = 1;
        params.credential.data.password = new SecretValue('string', '');

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();

        expect(disabledLogErrorStub).toHaveBeenCalledTimes(0);
    });

    it('enforces and does not throw when the config is 4', async () => {
        const params = await credentialRuleParam(vault);

        // @ts-expect-error Accessing a private var
        const disabledLogErrorStub = vi.spyOn(rule._log, 'error');

        params.config.credentialRestrictions.passwordComplexity.minCharacterCategories = 4;
        params.credential.data.password = new SecretValue('string', 'abc123ABC!@#');

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();

        expect(disabledLogErrorStub).toHaveBeenCalledTimes(0);
    });

    it('disables when the config is 0', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = vi.spyOn(rule._log, 'error');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.minCharacterCategories = 0;

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();

        expect(ruleLogErrorStub).toHaveBeenCalledWith(
            'Rule disabled: Configuration error: Min character category count can not be below 1'
        );
    });

    it('disables when the config is too high', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = vi.spyOn(rule._log, 'error');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.minCharacterCategories = 5;

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();

        expect(ruleLogErrorStub).toHaveBeenCalledWith(
            'Rule disabled: Configuration error: Min character category count can not be above 4'
        );
    });
});
