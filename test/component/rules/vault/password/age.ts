import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { vaultPasswordAge } from '../../../../../src/rules/vault/password/age.ts';
import { VaultRuleParameters } from '../../../../../src/vault/enforcable.ts';
import { getBaseVault } from '../../../support/base-vault.ts';
import { vaultRuleParams } from '../../../support/vault-rule-param.ts';

const hourInMilliseconds = 3600000;

describe('Vault security check: vault password age', async () => {
    const vault = await getBaseVault();
    const rulebook = new Rulebook<VaultRuleParameters>();
    let rule: Rule<VaultRuleParameters>;

    beforeEach(() => {
        rule = vaultPasswordAge();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.maxPasswordAge = Infinity;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('throws when the credential password is too old', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.maxPasswordAge = 10;
        vi.spyOn(params.vault, 'getVaultPasswordLastChangeDate').mockResolvedValue(
            new Date(new Date().getTime() - 15 * hourInMilliseconds)
        );

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            'Vault password is too old, change it'
        );
    });

    it('does not throw when the credential password not too old', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.maxPasswordAge = 10;
        vi.spyOn(params.vault, 'getVaultPasswordLastChangeDate').mockResolvedValue(
            new Date(new Date().getTime() - 5 * hourInMilliseconds)
        );

        await rulebook.enforce(rule.name, params);
    });

    it('disables when the config is 0', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = vi.spyOn(rule._log, 'error');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.maxPasswordAge = 0;

        await rulebook.enforce(rule.name, params);

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

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.maxPasswordAge = -5;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogErrorStub).toHaveBeenCalledWith(
            'Rule disabled: Configuration error: Max password age can not be equal to or below 0'
        );
    });

    it('disables when the config is Infinity', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.maxPasswordAge = Infinity;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: Disabled by security config `maxPasswordAge`'
        );
    });

    it('throws when the password age cant be found', async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.maxPasswordAge = 5;
        vi.spyOn(params.vault, 'getVaultPasswordLastChangeDate').mockResolvedValue(null);

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            'Could not find when the vault password was last changed. Assuming the worst.'
        );
    });
});
