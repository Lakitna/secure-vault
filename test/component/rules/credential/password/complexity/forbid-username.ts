import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { credentialPasswordComplexityForbidUsername } from '../../../../../../src/rules/credential/password/complexity/forbid-username.ts';
import { SecretValue } from '../../../../../../src/secret-value.ts';
import { CredentialRuleParameters } from '../../../../../../src/vault/enforcable.ts';
import { getBaseVault } from '../../../../support/base-vault.ts';
import { credentialRuleParam } from '../../../../support/credential-rule-param.ts';

const vault = await getBaseVault();
const rulebook = new Rulebook<CredentialRuleParameters>();
let rule: Rule<CredentialRuleParameters>;

describe('Credential security check: credential password forbid username', () => {
    beforeEach(() => {
        rule = credentialPasswordComplexityForbidUsername();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUsername = false;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('throws when the username contains the password', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUsername = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.username = 'lorum';

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            `Password contains (part of) username`
        );
    });

    it('throws when the username email contains the password', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUsername = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.username =
            'lorum@a-very-long-domain-name-that-may-cause-matching-to-be-difficult.com';

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            `Password contains (part of) username`
        );
    });

    it('disables when the config is false', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUsername = false;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.username = 'lorum';

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: Disabled by security config `forbidUsername`'
        );
    });

    it('does not throw when the password is different from the username', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUsername = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.username = 'something-else';

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
    });

    it('disables when there is no username', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUsername = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.username = '';

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: No username, nothing to check'
        );
    });

    it('disables when there is no password', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUsername = true;
        params.credential.data.password = new SecretValue('string', '');
        params.credential.data.username = 'my-username';

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: No password, nothing to check'
        );
    });

    it('does not throw when the username email domain matches', async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUsername = true;
        params.credential.data.password = new SecretValue('string', 'gmail');
        params.credential.data.username = 'my-username@gmail.com';

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
    });

    it('throws when the username is not quite email-like and matches the password', async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUsername = true;
        params.credential.data.password = new SecretValue('string', 'email');
        params.credential.data.username = 'not@email';

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            `Password contains (part of) username`
        );
    });

    it('throws when the username starts with @ and matches the password', async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUsername = true;
        params.credential.data.password = new SecretValue('string', 'email');
        params.credential.data.username = '@not@email';

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            `Password contains (part of) username`
        );
    });

    it('throws when the username inclues @ but no top-leevl domain and matches the password', async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUsername = true;
        params.credential.data.password = new SecretValue('string', 'gmail');
        params.credential.data.username = 'my-username@gmail';

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            `Password contains (part of) username`
        );
    });

    it('thows when the username starts with @ and matches the password', async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUsername = true;
        params.credential.data.password = new SecretValue('string', 'gmail');
        params.credential.data.username = '@gmail';

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            `Password contains (part of) username`
        );
    });
});
