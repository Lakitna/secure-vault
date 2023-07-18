import { expect } from 'chai';
import path from 'node:path';
import Rulebook, { Rule } from 'rulebound';
import sinon from 'sinon';
import { vaultRuleParameters } from '../../../../../src/security-checker';
import { keepassVaultStoredWithKeyfile } from '../../../../../src/security-checker/vault/keepass/vault-stored-with-keyfile';
import git from '../../../../../src/util/git';
import npm from '../../../../../src/util/npm';
import { getBaseVault } from '../../../support/base-vault';
import { vaultRuleParams } from '../../../support/vault-rule-param';

describe('Vault security check: vault stored with keyfile', () => {
    const vault = getBaseVault();
    const rulebook = new Rulebook<vaultRuleParameters>();
    let rule: Rule<vaultRuleParameters>;

    beforeEach(() => {
        rule = keepassVaultStoredWithKeyfile();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = true;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).to.equal(1);

        const rule = rulebook.rules[0];
        expect(rule.description).to.be.a('string');
        expect(rule.description?.length).to.be.above(0);
    });

    it('does not throw if no keyfile is used', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
        params.vaultCredential.multifactor = undefined;

        await rulebook.enforce(rule.name, params);
    });

    it('disables if config allows the vault to be stored with the keyfile', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = true;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Disabled by security config `allowVaultAndKeyfileSameLocation`'
        );
    });

    it('disables if config no keyfile is defined', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
        params.vaultCredential.multifactor = '';

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: No keyfile defined'
        );
    });

    context('Git repo', () => {
        it('throws when the vault is in the same git repo as the keyfile', async () => {
            const params = await vaultRuleParams(vault);
            params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
            params.vaultCredential.multifactor = vault.path;

            sinon.stub(git, 'getRoot').resolves('my/git/root/path');
            sinon.stub(git, 'isIgnored').resolves(false);

            await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
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

                sinon.stub(git, 'getRoot').resolves('my/git/root/path');
                sinon
                    .stub(git, 'isIgnored')
                    .onFirstCall()
                    .resolves(true)
                    .onSecondCall()
                    .resolves(false);

                await rulebook.enforce(rule.name, params);
            }
        );

        it(
            'does not throw when the vault is in the same git repo as the keyfile ' +
                'but the keyfile is gitignored',
            async () => {
                const params = await vaultRuleParams(vault);

                params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
                params.vaultCredential.multifactor = vault.path;

                sinon.stub(git, 'getRoot').resolves('my/git/root/path');
                sinon
                    .stub(git, 'isIgnored')
                    .onFirstCall()
                    .resolves(false)
                    .onSecondCall()
                    .resolves(true);

                await rulebook.enforce(rule.name, params);
            }
        );

        it('does not throw when the vault is in different git repo as the keyfile', async () => {
            const params = await vaultRuleParams(vault);

            params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
            params.vaultCredential.multifactor = 'some/amazing/random/path';

            sinon
                .stub(git, 'getRoot')
                .onFirstCall()
                .resolves('my/git/root/path')
                .onSecondCall()
                .resolves('another/git/root/path');
            sinon.stub(git, 'isIgnored').resolves(false);

            sinon.stub(npm, 'getRoot').resolves(false);

            await rulebook.enforce(rule.name, params);
        });
    });

    context('NPM project', () => {
        beforeEach(() => {
            const gitGetRootStub = sinon.stub(git, 'getRoot');
            gitGetRootStub.onFirstCall().resolves('my/git/root/path');
            gitGetRootStub.onSecondCall().resolves('another/git/root/path');
            sinon.stub(git, 'isIgnored').resolves(false);
        });

        it('throws when the vault is in the same npm project as the keyfile', async () => {
            const params = await vaultRuleParams(vault);

            params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
            params.vaultCredential.multifactor = vault.path;

            sinon.stub(npm, 'getRoot').resolves('my/npm/root/path');

            await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
                'Vault and keyfile are in the same NPM project @ my/npm/root/path'
            );
        });

        it('does not throw when the vault is in different npm project as the keyfile', async () => {
            const params = await vaultRuleParams(vault);

            params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
            params.vaultCredential.multifactor = 'some/amazing/random/path';

            sinon
                .stub(npm, 'getRoot')
                .onFirstCall()
                .resolves('my/npm/root/path')
                .onSecondCall()
                .resolves('another/npm/root/path');

            await rulebook.enforce(rule.name, params);
        });
    });

    context('Directory', () => {
        beforeEach(() => {
            sinon
                .stub(git, 'getRoot')
                .onFirstCall()
                .resolves('my/git/root/path')
                .onSecondCall()
                .resolves('another/git/root/path');
            sinon.stub(git, 'isIgnored').resolves(false);

            sinon
                .stub(npm, 'getRoot')
                .onFirstCall()
                .resolves('my/npm/root/path')
                .onSecondCall()
                .resolves('another/npm/root/path');
        });

        it('throws when the vault is in the same directory as the keyfile', async () => {
            const params = await vaultRuleParams(vault);

            params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
            params.vaultCredential.multifactor = path.join(
                path.dirname(vault.path),
                './keyfile.xml'
            );

            await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
                'Vault and keyfile are in the same directory @ ' + path.dirname(vault.path)
            );
        });

        it('does not throw when the vault is in different directory as the keyfile', async () => {
            const params = await vaultRuleParams(vault);

            params.config.vaultRestrictions.allowVaultAndKeyfileSameLocation = false;
            params.vaultCredential.multifactor = 'some/amazing/random/path';

            await rulebook.enforce(rule.name, params);
        });
    });
});
