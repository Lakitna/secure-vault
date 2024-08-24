import { describe, expect, it, vi } from 'vitest';
import { BaseVaultCredential } from '../../src/config/vault-password-prompt.ts';
import { SecretValue } from '../../src/secret-value.ts';
import { BaseVault, BaseVaultOptions } from '../../src/vault/vault.ts';

describe('Abstract vault', () => {
    it('constructs with default config', () => {
        // @ts-expect-error Make instance of abstract class
        const vault = new BaseVault({});

        expect(vault.id).toEqual('[unknown]');
        expect(vault.enforcable).toEqual(false);
        expect(vault.openable).toEqual(false);
        expect(vault.readable).toEqual(false);
        expect(vault.writable).toEqual(false);
    });

    it('constructs with user config', () => {
        const opts: BaseVaultOptions = {
            id: 'test',
        };

        // @ts-expect-error Make instance of abstract class
        const vault = new BaseVault(opts);

        expect(vault.id).toEqual('test');
        expect(vault.enforcable).toEqual(false);
        expect(vault.openable).toEqual(false);
        expect(vault.readable).toEqual(false);
        expect(vault.writable).toEqual(false);
    });

    describe.skip('getVaultCredential', () => {
        const userPromptStubReturn: BaseVaultCredential = {
            password: new SecretValue('string', 'some-password'),
            savePassword: false,
            vaultPath: 'vault-id',
            multifactor: undefined,
        };

        it('prompts the user if password save is not allowed', async () => {
            const forgetRememberedPasswordStub = vi.fn();
            const getRememberedPasswordStub = vi.fn();
            const rememberPasswordStub = vi.fn();
            const mockedModule = await esmock(
                '../../src/vault/vault.ts',
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
            const userPromptStub = vi.fn().resolves(userPromptStubReturn);

            const vault = new mockedModule.Vault({
                securityConfig: {
                    prompt: {
                        allowPasswordSave: false,
                    },
                },
            } as Partial<BaseVaultOptions>);
            const result = await vault.getVaultCredential(
                { vaultPath: 'vault-id', multifactor: undefined },
                true,
                userPromptStub
            );

            expect(forgetRememberedPasswordStub).to.have.been.calledOnce;
            expect(getRememberedPasswordStub).to.have.not.been.called;
            expect(userPromptStub).to.have.been.calledOnceWithExactly();
            expect(rememberPasswordStub).to.have.not.been.called;
            expect(result).to.deep.equal(userPromptStubReturn);
        });

        it('prompts the user if this is the second attempt to open the vault', async () => {
            const getRememberedPasswordStub = vi.fn();
            const rememberPasswordStub = vi.fn();
            const mockedModule = await esmock(
                '../../src/vault/vault.ts',
                import.meta.url,
                {
                    '../../src/util/remember-password.ts': {
                        getRememberedPassword: getRememberedPasswordStub,
                        rememberPassword: rememberPasswordStub,
                    },
                },
                {}
            );
            const userPromptStub = vi.fn().resolves(userPromptStubReturn);

            const vault = new mockedModule.Vault({
                securityConfig: {
                    prompt: {
                        allowPasswordSave: true,
                    },
                },
            } as Partial<BaseVaultOptions>);
            const result = await vault.getVaultCredential('vault-id', false, userPromptStub);

            expect(getRememberedPasswordStub).to.have.not.been.called;
            expect(userPromptStub).to.have.been.calledOnceWithExactly();
            expect(rememberPasswordStub).to.have.not.been.called;
            expect(result).to.deep.equal(userPromptStubReturn);
        });

        it('prompts after remembered password is not found', async () => {
            const getRememberedPasswordStub = vi.fn().resolves(null);
            const rememberPasswordStub = vi.fn();
            const mockedModule = await esmock(
                '../../src/vault/vault.ts',
                import.meta.url,
                {
                    '../../src/util/remember-password.ts': {
                        getRememberedPassword: getRememberedPasswordStub,
                        rememberPassword: rememberPasswordStub,
                    },
                },
                {}
            );
            const userPromptStub = vi.fn().resolves(userPromptStubReturn);

            const vault = new mockedModule.Vault({
                securityConfig: {
                    prompt: {
                        allowPasswordSave: true,
                    },
                },
            } as Partial<BaseVaultOptions>);
            const result = await vault.getVaultCredential(
                { vaultPath: 'vault-id', multifactor: undefined },
                true,
                userPromptStub
            );

            expect(getRememberedPasswordStub).to.have.been.calledOnceWithExactly('vault-id');
            expect(userPromptStub).to.have.been.calledOnceWithExactly();
            expect(rememberPasswordStub).to.have.not.been.called;
            expect(result).to.deep.equal(userPromptStubReturn);
        });

        it('does not prompt after remembered password is found', async () => {
            const getRememberedPasswordStub = sinon
                .stub()
                .resolves(new SecretValue('string', 'remembered-password'));
            const rememberPasswordStub = vi.fn();
            const mockedModule = await esmock(
                '../../src/vault/vault.ts',
                import.meta.url,
                {
                    '../../src/util/remember-password.ts': {
                        getRememberedPassword: getRememberedPasswordStub,
                        rememberPassword: rememberPasswordStub,
                    },
                },
                {}
            );
            const userPromptStub = vi.fn();
            const consoleLogStub = sinon.stub(console, 'log');

            const vault = new mockedModule.Vault({
                securityConfig: {
                    prompt: {
                        allowPasswordSave: true,
                    },
                },
            } as Partial<BaseVaultOptions>);
            const result = await vault.getVaultCredential(
                { vaultPath: 'vault-id', multifactor: undefined },
                true,
                userPromptStub
            );

            expect(getRememberedPasswordStub).to.have.been.calledOnceWithExactly('vault-id');
            expect(userPromptStub).to.have.not.been.called;
            expect(rememberPasswordStub).to.have.not.been.called;

            expect(result.password).to.be.instanceOf(SecretValue);
            expect(result.password.expose()).toEqual('remembered-password');
            expect(result.savePassword).toEqual(false);

            expect(consoleLogStub).to.have.been.calledOnceWithExactly(
                'Using remembered vault password'
            );
        });

        it('saves the password after prompting if the user wants it', async () => {
            const getRememberedPasswordStub = vi.fn();
            const rememberPasswordStub = vi.fn();
            const mockedModule = await esmock(
                '../../src/vault/vault.ts',
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
            } as Partial<BaseVaultOptions>);
            const result = await vault.getVaultCredential(
                { vaultPath: 'vault-id', multifactor: undefined },
                false,
                userPromptStub
            );

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
