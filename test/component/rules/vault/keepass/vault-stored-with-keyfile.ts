import path from 'node:path';
import Rulebook, { Rule } from 'rulebound';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import git from '../../../../../src/util/git.ts';
import npm from '../../../../../src/util/npm.ts';
import { VaultRuleParameters } from '../../../../../src/vault/enforcable.ts';
import { keepassVaultStoredWithKeyfile } from '../../../../../src/vault/keepass/rules/vault/vault-stored-with-keyfile.ts';
import { getBaseVault } from '../../../support/base-vault.ts';
import { vaultRuleParams } from '../../../support/vault-rule-param.ts';

const vault = await getBaseVault();
const rulebook = new Rulebook<VaultRuleParameters>();
let rule: Rule<VaultRuleParameters>;

describe('Vault security check: vault stored with keyfile', () => {
    beforeEach(() => {
        rule = keepassVaultStoredWithKeyfile();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    afterAll(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = true;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).toEqual(1);

        const rule = rulebook.rules[0];
        expect(rule.description).toBeTypeOf('string');
        expect(rule.description?.length).toBeGreaterThan(0);
    });

    it('does not throw if no keyfile is used', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
        params.vaultCredential.multifactor = undefined;

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
    });

    it('disables if config allows the vault to be stored with the keyfile', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = true;

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();

        expect(ruleLogDebugStub).toHaveBeenCalledWith(
            'Rule disabled: Disabled by security config `allowVaultAndKeyfileSameLocation`'
        );
    });

    it('disables if config no keyfile is defined', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = vi.spyOn(rule._log, 'debug');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
        params.vaultCredential.multifactor = '';

        await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();

        expect(ruleLogDebugStub).toHaveBeenCalledWith('Rule disabled: No keyfile defined');
    });

    describe('Git repo', () => {
        it('throws when the vault is in the same git repo as the keyfile', async () => {
            const params = await vaultRuleParams(vault);
            params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
            params.vaultCredential.multifactor = vault.path;

            vi.spyOn(git, 'getRoot').mockResolvedValue('my/git/root/path');
            vi.spyOn(git, 'isIgnored').mockResolvedValue(false);

            await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
                'Vault and keyfile are in the same Git repository @ my/git/root/path'
            );
        });

        it(
            'does not throw when the vault is in the same git repo as the keyfile ' +
                'but the vault is gitignored',
            async () => {
                const params = await vaultRuleParams(vault);

                params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
                params.vaultCredential.multifactor = vault.path;

                vi.spyOn(git, 'getRoot').mockResolvedValue('my/git/root/path');
                vi.spyOn(git, 'isIgnored').mockResolvedValueOnce(true).mockResolvedValue(false);

                await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
            }
        );

        it(
            'does not throw when the vault is in the same git repo as the keyfile ' +
                'but the keyfile is gitignored',
            async () => {
                const params = await vaultRuleParams(vault);

                params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
                params.vaultCredential.multifactor = vault.path;

                vi.spyOn(git, 'getRoot').mockResolvedValue('my/git/root/path');
                vi.spyOn(git, 'isIgnored').mockResolvedValueOnce(false).mockResolvedValue(true);

                await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
            }
        );

        it('does not throw when the vault is in different git repo as the keyfile', async () => {
            const params = await vaultRuleParams(vault);

            params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
            params.vaultCredential.multifactor = 'some/amazing/random/path';

            vi.spyOn(git, 'getRoot')
                .mockResolvedValueOnce('my/git/root/path')
                .mockResolvedValue('another/git/root/path');
            vi.spyOn(git, 'isIgnored').mockResolvedValue(false);

            vi.spyOn(npm, 'getRoot').mockResolvedValue(false);

            await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
        });
    });

    describe('NPM project', () => {
        beforeEach(() => {
            vi.spyOn(git, 'getRoot')
                .mockResolvedValueOnce('my/git/root/path')
                .mockResolvedValueOnce('another/git/root/path');
            vi.spyOn(git, 'isIgnored').mockResolvedValue(false);
        });

        it('throws when the vault is in the same npm project as the keyfile', async () => {
            const params = await vaultRuleParams(vault);

            params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
            params.vaultCredential.multifactor = vault.path;

            vi.spyOn(npm, 'getRoot').mockResolvedValue('my/npm/root/path');

            await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
                'Vault and keyfile are in the same NPM project @ my/npm/root/path'
            );
        });

        it('does not throw when the vault is in different npm project as the keyfile', async () => {
            const params = await vaultRuleParams(vault);

            params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
            params.vaultCredential.multifactor = 'some/amazing/random/path';

            vi.spyOn(npm, 'getRoot')
                .mockResolvedValueOnce('my/npm/root/path')
                .mockResolvedValue('another/npm/root/path');

            await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
        });
    });

    describe('Directory', () => {
        beforeEach(() => {
            vi.spyOn(git, 'getRoot')
                .mockResolvedValueOnce('my/git/root/path')

                .mockResolvedValue('another/git/root/path');
            vi.spyOn(git, 'isIgnored').mockResolvedValue(false);

            vi.spyOn(npm, 'getRoot')
                .mockResolvedValueOnce('my/npm/root/path')
                .mockResolvedValue('another/npm/root/path');
        });

        it('throws when the vault is in the same directory as the keyfile', async () => {
            const params = await vaultRuleParams(vault);

            params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
            params.vaultCredential.multifactor = path.join(
                path.dirname(vault.path),
                './keyfile.xml'
            );

            await expect(rulebook.enforce(rule.name, params)).rejects.toThrow(
                'Vault and keyfile are in the same directory @ ' + path.dirname(vault.path)
            );
        });

        it('does not throw when the vault is in different directory as the keyfile', async () => {
            const params = await vaultRuleParams(vault);

            params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
            params.vaultCredential.multifactor = 'some/amazing/random/path';

            await expect(rulebook.enforce(rule.name, params)).resolves.not.toThrow();
        });
    });
});
