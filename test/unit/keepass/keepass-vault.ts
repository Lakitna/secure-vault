import { expect } from 'chai';
import sinon from 'sinon';
import { KeepassVault } from '../../../src';
import { Vault } from '../../../src/vault';

describe.skip('Keepass vault', () => {
    it('constructs with default config', () => {
        const vault = new KeepassVault('i/do/not/exist');

        expect(vault).to.be.instanceOf(Vault);
        expect(vault.securityConfig).to.be.an('object');

        expect(vault.keyfilePath).to.be.undefined;
        expect(vault.path).to.equal('i/do/not/exist');
    });

    describe('open', () => {
        it('opens a vault file', () => {
            const vault = new KeepassVault('some/vault-file/path');

            const getVaultCredentialStub = sinon.stub(vault, 'getVaultCredential');
        });
    });
});
