import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { credentialRequireExpiration } from '../../../../src/rules/credential/credential-require-expiration.ts';
import { CredentialRuleParameters } from '../../../../src/vault/enforcable.ts';
import { getBaseVault } from '../../support/base-vault.ts';
import { credentialRuleParam } from '../../support/credential-rule-param.ts';

const vault = await getBaseVault();
const rulebook = new Rulebook<CredentialRuleParameters>();
let rule: Rule<CredentialRuleParameters>;

describe('Credential security check: credential require expiration', () => {
    beforeEach(() => {
        rule = credentialRequireExpiration();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.requireExpiration = false;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('throws when the credential has no expiration date', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.requireExpiration = true;
        params.credential.hasExpiration = false;

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            'Credential has no exipiration date'
        );
    });

    it('does not throw when the credential has expiration date', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.requireExpiration = true;
        params.credential.hasExpiration = true;

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
    });

    it('disables when no expiration date is required', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.requireExpiration = false;
        params.credential.hasExpiration = false;

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: Disabled by security config `requireExpiration`'
        );
    });
});
