import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { credentialPasswordComplexityForbidReuse } from '../../../../../../src/rules/credential/password/complexity/forbid-reuse.ts';
import { SecretValue } from '../../../../../../src/secret-value.ts';
import { CredentialRuleParameters } from '../../../../../../src/vault/enforcable.ts';
import { getBaseVault } from '../../../../support/base-vault.ts';
import { credentialRuleParam } from '../../../../support/credential-rule-param.ts';

const vault = await getBaseVault();
const rulebook = new Rulebook<CredentialRuleParameters>();
let rule: Rule<CredentialRuleParameters>;

describe('Credential security check: credential password forbid reuse', () => {
    beforeEach(() => {
        rule = credentialPasswordComplexityForbidReuse();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidReuse = false;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('throws when the password is reused', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidReuse = true;
        // The vault contains a credential with password 'lorum-ipsum'
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            `Credential password is used by another credential: 'Root/lorum'`
        );
    });

    it('disables when the config is false', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidReuse = false;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: Disabled by security config `forbidReuse`'
        );
    });

    it('does not throw when the password is unique', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidReuse = true;
        params.credential.data.password = new SecretValue('string', 'orum-ipsum');

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
    });

    it('disables when the credential has no password', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidReuse = true;
        params.credential.data.password = new SecretValue('string', '');

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: No password, nothing to check'
        );
    });
});
