import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { credentialAllowExpired } from '../../../../src/rules/credential/credential-allow-expired.ts';
import { CredentialRuleParameters } from '../../../../src/vault/enforcable.ts';
import { getBaseVault } from '../../support/base-vault.ts';
import { credentialRuleParam } from '../../support/credential-rule-param.ts';

describe('Credential security check: allow expired credential', async () => {
    const vault = await getBaseVault();
    const rulebook = new Rulebook<CredentialRuleParameters>();
    let rule: Rule<CredentialRuleParameters>;

    beforeEach(() => {
        rule = credentialAllowExpired();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.allowExpired = true;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('throws when the credential is expired', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.allowExpired = false;
        params.credential.expired = true;

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow('Credential expired');
    });

    it('does not throw if the credential is not expired', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.allowExpired = false;
        params.credential.expired = false;

        await rulebook.enforce(rule.name, params);
    });

    it('disables if expired credentials are allowed', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.allowExpired = true;
        params.credential.expired = true;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: Disabled by security config `allowExpired`'
        );
    });
});
