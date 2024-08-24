import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import file from '../../../../../../src/util/file-with-code.ts';
import { VaultRuleParameters } from '../../../../../../src/vault/enforcable.ts';
import { keepassVaultKeyfileStoredWithCode } from '../../../../../../src/vault/keepass/rules/vault/keyfile/keyfile-stored-with-code.ts';
import { getBaseVault } from '../../../../support/base-vault.ts';
import { vaultRuleParams } from '../../../../support/vault-rule-param.ts';

const vault = await getBaseVault();
const rulebook = new Rulebook<VaultRuleParameters>();
let rule: Rule<VaultRuleParameters>;

describe('Vault security check: keyfile stored with code', () => {
    beforeEach(() => {
        rule = keepassVaultKeyfileStoredWithCode();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.allowKeyfileWithCode = true;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('throws when the keyfile is stored with code', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.allowKeyfileWithCode = false;
        const stub = vi.spyOn(file, 'fileWithCode').mockResolvedValue(true);
        params.vaultCredential.multifactor = 'path/to/keyfile';

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            'Keyfile is stored with source code'
        );
        expect(stub).toHaveBeenCalled();
    });

    it('does not throw when the keyfile is not stored with code', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.allowKeyfileWithCode = false;
        const stub = vi.spyOn(file, 'fileWithCode').mockResolvedValue(false);
        params.vaultCredential.multifactor = 'path/to/keyfile';

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
        params.config.vaultRestrictions.allowKeyfileWithCode = true;
        const stub = vi.spyOn(file, 'fileWithCode').mockResolvedValue(true);
        params.vaultCredential.multifactor = 'path/to/keyfile';

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
        expect(stub).toHaveBeenCalledTimes(0);

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: Disabled by security config `allowKeyfileWithCode`'
        );
    });

    it('disables when there is no keyfile', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.allowKeyfileWithCode = false;
        const stub = vi.spyOn(file, 'fileWithCode').mockResolvedValue(true);
        params.vaultCredential.multifactor = undefined;

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
        expect(stub).toHaveBeenCalledTimes(0);

        expect(ruleLogDebugStub).toHaveBeenCalledWith('Rule disabled: No keyfile defined');
    });
});
