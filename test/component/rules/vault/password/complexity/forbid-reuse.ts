import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { vaultPasswordComplexityCharacterForbidReuse } from '../../../../../../src/rules/vault/password/complexity/forbid-reuse.ts';
import { SecretValue } from '../../../../../../src/secret-value.ts';
import { VaultRuleParameters } from '../../../../../../src/vault/enforcable.ts';
import { getBaseVault } from '../../../../support/base-vault.ts';
import { vaultRuleParams } from '../../../../support/vault-rule-param.ts';

describe('Vault security check: vault password forbid reuse', async () => {
    const vault = await getBaseVault();
    const rulebook = new Rulebook<VaultRuleParameters>();
    let rule: Rule<VaultRuleParameters>;

    beforeEach(() => {
        rule = vaultPasswordComplexityCharacterForbidReuse();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.passwordComplexity.forbidReuse = false;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('throws when the password is also used by a credential', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidReuse = true;
        // The vault contains a credential with password 'lorum-ipsum'
        params.vaultCredential.password = new SecretValue('string', 'lorum-ipsum');

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            `Vault password is also used by 1 credential(s)`
        );
    });

    it('disables when the config is false', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidReuse = false;
        params.vaultCredential.password = new SecretValue('string', 'lorum-ipsum');

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: Disabled by security config `forbidReuse`'
        );
    });

    it('disables when the vault has no password', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidReuse = true;
        params.vaultCredential.password = new SecretValue('string', '');

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).toHaveBeenCalledWith('Rule disabled: No vault password');
    });

    it('does not throw when the password is unique', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidReuse = true;
        // The vault contains a credential with password 'lorum-ipsum'
        params.vaultCredential.password = new SecretValue('string', 'orum-ipsum');

        await rulebook.enforce(rule.name, params);
    });
});
