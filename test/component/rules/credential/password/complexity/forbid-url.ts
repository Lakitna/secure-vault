import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { credentialPasswordComplexityForbidUrl } from '../../../../../../src/rules/credential/password/complexity/forbid-url.ts';
import { SecretValue } from '../../../../../../src/secret-value.ts';
import { CredentialRuleParameters } from '../../../../../../src/vault/enforcable.ts';
import { getBaseVault } from '../../../../support/base-vault.ts';
import { credentialRuleParam } from '../../../../support/credential-rule-param.ts';

describe('Credential security check: credential password forbid url', async () => {
    const vault = await getBaseVault();
    const rulebook = new Rulebook<CredentialRuleParameters>();
    let rule: Rule<CredentialRuleParameters>;

    beforeEach(() => {
        rule = credentialPasswordComplexityForbidUrl();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUrl = false;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('throws when the url contains the password', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.url = 'https://lorum.ipsum.org';

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            `Password contains (part of) URL domain`
        );
    });

    it('throws when the password contains the IP URL', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', '127.0.0');
        params.credential.data.url = 'https://127.0.0.1:8000';

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            `Password contains (part of) URL domain`
        );
    });

    it('disables when the config is false', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUrl = false;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: Disabled by security config `forbidUrl`'
        );
    });

    it('does not throw when the password is different from the url', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.url = 'https://google.com';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the matching bit is in the url path', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.url = 'https://google.com/lorum/ipsum/dolor';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the matching bit is a short domain part', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', 'agglcomagglcom');
        params.credential.data.url = 'https://a.ggl.com';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the matching bit is in the url query string parameters', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.url = 'https://google.com?lorum=ipsum';

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the matching bit is in the url fragment', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.url = 'https://google.com#lorum-ipsum';

        await rulebook.enforce(rule.name, params);
    });

    it('disables when there is no url', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');
        params.credential.data.url = '';

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).toHaveBeenCalledWith('Rule disabled: Credential has no URL');
    });

    it('disables when there is no password', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidUrl = true;
        params.credential.data.password = new SecretValue('string', '');
        params.credential.data.url = 'https://google.com';

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).toHaveBeenCalledWith('Rule disabled: Credential has no password');
    });
});
