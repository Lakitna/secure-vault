import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretValue } from '../../../../../../src/secret-value.ts';
import { VaultRuleParameters } from '../../../../../../src/vault/enforcable.ts';
import { fileVaultPasswordComplexityCharacterForbidVaultPath } from '../../../../../../src/vault/file/rules/vault/password/forbid-vault-path.ts';
import { getBaseVault } from '../../../../support/base-vault.ts';
import { vaultRuleParams } from '../../../../support/vault-rule-param.ts';

describe('Vault security check: vault password forbid vault path', async () => {
    const vault = await getBaseVault();
    const rulebook = new Rulebook<VaultRuleParameters>();
    let rule: Rule<VaultRuleParameters>;

    beforeEach(() => {
        rule = fileVaultPasswordComplexityCharacterForbidVaultPath();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.passwordComplexity.forbidVaultPath = false;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('throws when the vault path contains the password', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidVaultPath = true;
        params.vaultCredential.password = new SecretValue('string', 'lorum-ipsum');
        params.vaultCredential.vaultPath = '/some/file/path/lorum/ipsum.kdbx';

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            `Vault password contains (part of) the vault file path`
        );
    });

    it('disables when the config is false', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.passwordComplexity.forbidVaultPath = false;
        params.vaultCredential.password = new SecretValue('string', 'lorum-ipsum');
        params.vaultCredential.vaultPath = '/some/file/path/lorum/ipsum.kdbx';

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: Disabled by security config `forbidVaultPath`'
        );
    });

    it('does not throw when the password is different from the vault path', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.passwordComplexity.forbidVaultPath = true;
        params.vaultCredential.password = new SecretValue('string', 'lorum-ipsum');
        params.vaultCredential.vaultPath = '/some/file/path/vault.kdbx';

        await rulebook.enforce(rule.name, params);
    });

    it('disables when there is no password', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.passwordComplexity.forbidVaultPath = true;
        params.vaultCredential.password = new SecretValue('string', '');
        params.vaultCredential.vaultPath = '/some/file/path/vault.kdbx';

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: No vault password, nothing to check'
        );
    });
});
