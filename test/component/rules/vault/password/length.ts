import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { vaultPasswordLength } from '../../../../../src/rules/vault/password/length.ts';
import { SecretValue } from '../../../../../src/secret-value.ts';
import { VaultRuleParameters } from '../../../../../src/vault/enforcable.ts';
import { getBaseVault } from '../../../support/base-vault.ts';
import { vaultRuleParams } from '../../../support/vault-rule-param.ts';

const vault = await getBaseVault();
const rulebook = new Rulebook<VaultRuleParameters>();
let rule: Rule<VaultRuleParameters>;

describe('Vault security check: vault password length', () => {
    beforeEach(() => {
        rule = vaultPasswordLength();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.minPasswordLength = 1;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('throws when the vault password is too short', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.minPasswordLength = 10;
        params.vaultCredential.password = new SecretValue('string', 'short');

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            'Vault password too short. Should be at least 10 characters.'
        );
    });

    it('does not throw when the vault password is the exact min lenght', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.minPasswordLength = 10;
        params.vaultCredential.password = new SecretValue('string', '0123456789');

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
    });

    it('does not throw when the vault password is longer than minimum', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.minPasswordLength = 3;
        params.vaultCredential.password = new SecretValue('string', '0123456789');

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
    });

    it('does not throw when the config is 0', async () => {
        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = vi.spyOn(rule._log, 'error');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.minPasswordLength = 0;

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();

        expect(ruleLogErrorStub).toHaveBeenCalledTimes(0);
    });

    it('disables when the config is below 0', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = vi.spyOn(rule._log, 'error');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.minPasswordLength = -5;

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();

        expect(ruleLogErrorStub).toHaveBeenCalledWith(
            'Rule disabled: Configuration error: Min password length can not be below 0'
        );
    });
});
