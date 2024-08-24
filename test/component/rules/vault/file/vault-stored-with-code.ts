import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import file from '../../../../../src/util/file-with-code.ts';
import { VaultRuleParameters } from '../../../../../src/vault/enforcable.ts';
import { fileVaultStoredWithCode } from '../../../../../src/vault/file/rules/vault/vault-stored-with-code.ts';
import { getBaseVault } from '../../../support/base-vault.ts';
import { vaultRuleParams } from '../../../support/vault-rule-param.ts';

const vault = await getBaseVault();
const rulebook = new Rulebook<VaultRuleParameters>();
let rule: Rule<VaultRuleParameters>;

describe('Vault security check: vault stored with code', () => {
    beforeEach(() => {
        rule = fileVaultStoredWithCode();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.allowVaultWithCode = true;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('throws when the vault is stored with code', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.allowVaultWithCode = false;
        const stub = vi.spyOn(file, 'fileWithCode').mockResolvedValue(true);

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            'Vault is stored with source code'
        );
        expect(stub).toHaveBeenCalled();
    });

    it('does not throw when the vault is not stored with code', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.allowVaultWithCode = false;
        const stub = vi.spyOn(file, 'fileWithCode').mockResolvedValue(false);

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
        expect(stub).toHaveBeenCalled();
    });

    it('disables when storing with code is allowed', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.allowVaultWithCode = true;
        const stub = vi.spyOn(file, 'fileWithCode').mockResolvedValue(true);

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();

        expect(stub).toHaveBeenCalledTimes(0);
        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: Disabled by security config `allowVaultWithCode`'
        );
    });
});
