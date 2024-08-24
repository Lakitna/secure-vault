import { Kdbx } from 'kdbxweb';
import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { VaultRuleParameters } from '../../../../../src/vault/enforcable.ts';
import { VaultRuleParametersKeepass } from '../../../../../src/vault/keepass/keepass-vault.ts';
import { keepassVaultDecryptionTime } from '../../../../../src/vault/keepass/rules/vault/vault-decryption-time.ts';
import { getBaseVault } from '../../../support/base-vault.ts';
import { vaultRuleParams } from '../../../support/vault-rule-param.ts';

describe('Vault security check: vault decryption time', async () => {
    const vault = await getBaseVault();
    const rulebook = new Rulebook<VaultRuleParameters>();
    let rule: Rule<VaultRuleParameters>;

    beforeEach(() => {
        rule = keepassVaultDecryptionTime();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.minDecryptionTime = 0;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('throws when the decryption time is too short', async () => {
        const params = (await vaultRuleParams(vault)) as VaultRuleParametersKeepass & {
            vault: { vault: Kdbx };
        };

        params.config.vaultRestrictions.minDecryptionTime = 100;
        params.vault.vault.meta.customData.set('KPXC_DECRYPTION_TIME_PREFERENCE', { value: '50' });

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            'Vault decryption time is too short. Should be at least 100ms.'
        );
    });

    it('does not throw when the decryption time is the exact min lenght', async () => {
        const params = (await vaultRuleParams(vault)) as VaultRuleParametersKeepass & {
            vault: { vault: Kdbx };
        };

        params.config.vaultRestrictions.minDecryptionTime = 100;
        params.vault.vault.meta.customData.set('KPXC_DECRYPTION_TIME_PREFERENCE', { value: '100' });

        await rulebook.enforce(rule.name, params);
    });

    it('does not throw when the decryption time is longer than minimum', async () => {
        const params = (await vaultRuleParams(vault)) as VaultRuleParametersKeepass & {
            vault: { vault: Kdbx };
        };

        params.config.vaultRestrictions.minDecryptionTime = 0;
        params.vault.vault.meta.customData.set('KPXC_DECRYPTION_TIME_PREFERENCE', {
            value: '1000',
        });

        await rulebook.enforce(rule.name, params);
    });

    it('disables when the decryption time is not set in the vault', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = (await vaultRuleParams(vault)) as VaultRuleParametersKeepass & {
            vault: { vault: Kdbx };
        };

        params.config.vaultRestrictions.minDecryptionTime = 100;
        params.vault.vault.meta.customData.set('KPXC_DECRYPTION_TIME_PREFERENCE', {
            value: undefined,
        });

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: Could not fetch decryption time from vault'
        );
    });

    it('disables when the config is below 0', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = vi.spyOn(rule._log, 'error');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.minDecryptionTime = -5;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogErrorStub).toHaveBeenCalledWith(
            'Rule disabled: Configuration error: Min decryption time can not be below 0'
        );
    });
});
