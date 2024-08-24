import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { VaultRuleParameters } from '../../../../../../src/vault/enforcable.ts';
import { keepassVaultKeyfileRequire } from '../../../../../../src/vault/keepass/rules/vault/keyfile/keyfile-require.ts';
import { getBaseVault } from '../../../../support/base-vault.ts';
import { vaultRuleParams } from '../../../../support/vault-rule-param.ts';

describe('Vault security check: require keyfile', async () => {
    const vault = await getBaseVault();
    const rulebook = new Rulebook<VaultRuleParameters>();
    let rule: Rule<VaultRuleParameters>;

    beforeEach(() => {
        rule = keepassVaultKeyfileRequire();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.requireKeyfile = false;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('throws when there is no keyfile', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.requireKeyfile = true;
        params.vaultCredential.multifactor = undefined;

        await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
            'Vault requires keyfile as second authentication factor'
        );
    });

    it('does not throw when there is a keyfile', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.requireKeyfile = true;
        params.vaultCredential.multifactor = 'path/to/keyfile';

        await rulebook.enforce(rule.name, params);
    });

    it('disables when a keyfile is not required', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.requireKeyfile = false;
        params.vaultCredential.multifactor = undefined;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: Disabled by security config `requireKeyfile`'
        );
    });
});
