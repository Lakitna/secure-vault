import { expect } from 'chai';
import esmock from 'esmock';
import sinon from 'sinon';
import { SecretValue } from '../../src';
import { BaseVaultCredential } from '../../src/config/vault-password-prompt';
import { Vault, VaultOptions } from '../../src/vault';

describe('Abstract vault', () => {
    it('constructs with default config', () => {
        // @ts-expect-error Make instance of abstract class
        const vault = new Vault({});

        expect(vault.readonly).to.be.true;
        expect(vault.logLevel).to.equal('info');
        expect(vault.securityConfig._presetName).to.equal('better');
    });

    it('constructs with user config', () => {
        const opts: VaultOptions = {
            readonly: false,
            logLevel: 'warn',
            securityConfig: 'none',
        };

        // @ts-expect-error Make instance of abstract class
        const vault = new Vault(opts);

        expect(vault.readonly).to.be.false;
        expect(vault.logLevel).to.equal('warn');
        expect(vault.securityConfig._presetName).to.equal('none');
    });

    describe('getVaultCredential', () => {
        const userPromptStubReturn: BaseVaultCredential = {
            password: new SecretValue('string', 'some-password'),
            savePassword: false,
        };

        it('prompts the user if password save is not allowed', async () => {
            const forgetRememberedPasswordStub = sinon.stub();
            const getRememberedPasswordStub = sinon.stub();
            const rememberPasswordStub = sinon.stub();
            const mockedModule = await esmock(
                '../../src/vault.ts',
                import.meta.url,
                {
                    '../../src/util/remember-password.ts': {
                        forgetRememberedPassword: forgetRememberedPasswordStub,
                        getRememberedPassword: getRememberedPasswordStub,
                        rememberPassword: rememberPasswordStub,
                    },
                },
                {}
            );
            const userPromptStub = sinon.stub().resolves(userPromptStubReturn);

            const vault = new mockedModule.Vault({
                securityConfig: {
                    prompt: {
                        allowPasswordSave: false,
                    },
                },
            } as Partial<VaultOptions>);
            const result = await vault.getVaultCredential('vault-id', true, userPromptStub);

            expect(forgetRememberedPasswordStub).to.have.been.calledOnce;
            expect(getRememberedPasswordStub).to.have.not.been.called;
            expect(userPromptStub).to.have.been.calledOnceWithExactly();
            expect(rememberPasswordStub).to.have.not.been.called;
            expect(result).to.deep.equal(userPromptStubReturn);
        });

        it('prompts the user if this is the second attempt to open the vault', async () => {
            const getRememberedPasswordStub = sinon.stub();
            const rememberPasswordStub = sinon.stub();
            const mockedModule = await esmock(
                '../../src/vault.ts',
                import.meta.url,
                {
                    '../../src/util/remember-password.ts': {
                        getRememberedPassword: getRememberedPasswordStub,
                        rememberPassword: rememberPasswordStub,
                    },
                },
                {}
            );
            const userPromptStub = sinon.stub().resolves(userPromptStubReturn);

            const vault = new mockedModule.Vault({
                securityConfig: {
                    prompt: {
                        allowPasswordSave: true,
                    },
                },
            } as Partial<VaultOptions>);
            const result = await vault.getVaultCredential('vault-id', false, userPromptStub);

            expect(getRememberedPasswordStub).to.have.not.been.called;
            expect(userPromptStub).to.have.been.calledOnceWithExactly();
            expect(rememberPasswordStub).to.have.not.been.called;
            expect(result).to.deep.equal(userPromptStubReturn);
        });

        it('prompts after remembered password is not found', async () => {
            const getRememberedPasswordStub = sinon.stub().resolves(null);
            const rememberPasswordStub = sinon.stub();
            const mockedModule = await esmock(
                '../../src/vault.ts',
                import.meta.url,
                {
                    '../../src/util/remember-password.ts': {
                        getRememberedPassword: getRememberedPasswordStub,
                        rememberPassword: rememberPasswordStub,
                    },
                },
                {}
            );
            const userPromptStub = sinon.stub().resolves(userPromptStubReturn);

            const vault = new mockedModule.Vault({
                securityConfig: {
                    prompt: {
                        allowPasswordSave: true,
                    },
                },
            } as Partial<VaultOptions>);
            const result = await vault.getVaultCredential('vault-id', true, userPromptStub);

            expect(getRememberedPasswordStub).to.have.been.calledOnceWithExactly('vault-id');
            expect(userPromptStub).to.have.been.calledOnceWithExactly();
            expect(rememberPasswordStub).to.have.not.been.called;
            expect(result).to.deep.equal(userPromptStubReturn);
        });

        it('does not prompt after remembered password is found', async () => {
            const getRememberedPasswordStub = sinon
                .stub()
                .resolves(new SecretValue('string', 'remembered-password'));
            const rememberPasswordStub = sinon.stub();
            const mockedModule = await esmock(
                '../../src/vault.ts',
                import.meta.url,
                {
                    '../../src/util/remember-password.ts': {
                        getRememberedPassword: getRememberedPasswordStub,
                        rememberPassword: rememberPasswordStub,
                    },
                },
                {}
            );
            const userPromptStub = sinon.stub();
            const consoleLogStub = sinon.stub(console, 'log');

            const vault = new mockedModule.Vault({
                securityConfig: {
                    prompt: {
                        allowPasswordSave: true,
                    },
                },
            } as Partial<VaultOptions>);
            const result = await vault.getVaultCredential('vault-id', true, userPromptStub);

            expect(getRememberedPasswordStub).to.have.been.calledOnceWithExactly('vault-id');
            expect(userPromptStub).to.have.not.been.called;
            expect(rememberPasswordStub).to.have.not.been.called;

            expect(result.password).to.be.instanceOf(SecretValue);
            expect(result.password.expose()).to.equal('remembered-password');
            expect(result.savePassword).to.be.false;

            expect(consoleLogStub).to.have.been.calledOnceWithExactly(
                'Using remembered vault password'
            );
        });

        it('saves the password after prompting if the user wants it', async () => {
            const getRememberedPasswordStub = sinon.stub();
            const rememberPasswordStub = sinon.stub();
            const mockedModule = await esmock(
                '../../src/vault.ts',
                import.meta.url,
                {
                    '../../src/util/remember-password.ts': {
                        getRememberedPassword: getRememberedPasswordStub,
                        rememberPassword: rememberPasswordStub,
                    },
                },
                {}
            );
            const userPromptStub = sinon
                .stub()
                .resolves({ ...userPromptStubReturn, savePassword: true });
            const consoleLogStub = sinon.stub(console, 'log');

            const vault = new mockedModule.Vault({
                securityConfig: {
                    prompt: {
                        allowPasswordSave: true,
                    },
                },
            } as Partial<VaultOptions>);
            const result = await vault.getVaultCredential('vault-id', false, userPromptStub);

            expect(getRememberedPasswordStub).to.have.not.been.called;
            expect(userPromptStub).to.have.been.calledOnceWithExactly();
            expect(rememberPasswordStub).to.have.been.calledOnceWithExactly(
                'vault-id',
                userPromptStubReturn.password
            );

            expect(result).to.deep.equal({ ...userPromptStubReturn, savePassword: true });

            expect(consoleLogStub).to.have.been.calledOnceWithExactly(
                '✅ Remembered vault password'
            );
        });
    });
});
