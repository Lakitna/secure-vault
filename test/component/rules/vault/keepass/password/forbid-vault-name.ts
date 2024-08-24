import { Kdbx } from 'kdbxweb';
import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretValue } from '../../../../../../src/secret-value.ts';
import { VaultRuleParameters } from '../../../../../../src/vault/enforcable.ts';
import { VaultRuleParametersKeepass } from '../../../../../../src/vault/keepass/keepass-vault.ts';
import { keepassVaultPasswordComplexityCharacterForbidVaultName } from '../../../../../../src/vault/keepass/rules/vault/password/forbid-vault-name.ts';
import { getBaseVault } from '../../../../support/base-vault.ts';
import { vaultRuleParams } from '../../../../support/vault-rule-param.ts';

describe('Vault security check: vault password forbid vault name', async () => {
    const vault = await getBaseVault();
    const rulebook = new Rulebook<VaultRuleParameters>();
    let rule: Rule<VaultRuleParameters>;

    beforeEach(() => {
        rule = keepassVaultPasswordComplexityCharacterForbidVaultName();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.passwordComplexity.forbidVaultName = false;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('throws when the vault name contains the password', async () => {
        const params = (await vaultRuleParams(vault)) as VaultRuleParametersKeepass & {
            vault: { vault: Kdbx };
        };

        params.config.vaultRestrictions.passwordComplexity.forbidVaultName = true;
        params.vaultCredential.password = new SecretValue('string', 'lorsum');
        params.vault.vault.meta.name = 'lorum-ipsum';

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            `Vault password contains (part of) the vault name`
        );
    });

    it('disables when the config is false', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = (await vaultRuleParams(vault)) as VaultRuleParametersKeepass & {
            vault: { vault: Kdbx };
        };
        params.config.vaultRestrictions.passwordComplexity.forbidVaultName = false;
        params.vaultCredential.password = new SecretValue('string', 'lorum');
        params.vault.vault.meta.name = 'lorum-ipsum';

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: Disabled by security config `forbidVaultName`'
        );
    });

    it('does not throw when the password is different from the vault name', async () => {
        const params = (await vaultRuleParams(vault)) as VaultRuleParametersKeepass & {
            vault: { vault: Kdbx };
        };

        params.config.vaultRestrictions.passwordComplexity.forbidVaultName = true;
        params.vaultCredential.password = new SecretValue('string', 'some-other-password');
        params.vault.vault.meta.name = 'lorum-ipsum';

        await rulebook.enforce(rule.name, params);
    });

    it('disables when there is no password', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = (await vaultRuleParams(vault)) as VaultRuleParametersKeepass & {
            vault: { vault: Kdbx };
        };
        params.config.vaultRestrictions.passwordComplexity.forbidVaultName = true;
        params.vaultCredential.password = new SecretValue('string', '');
        params.vault.vault.meta.name = 'lorum-ipsum';

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: No vault password, nothing to check'
        );
    });

    it('disables when there is no vault name', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = (await vaultRuleParams(vault)) as VaultRuleParametersKeepass & {
            vault: { vault: Kdbx };
        };

        params.config.vaultRestrictions.passwordComplexity.forbidVaultName = true;
        params.vaultCredential.password = new SecretValue('string', 'lorum');
        params.vault.vault.meta.name = '';

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: No vault name, nothing to check'
        );
    });
});
