import { expect } from 'chai';
import { KeepassVault } from '../../src';

describe('Keepass vault', () => {
    it('constructs with default config', () => {
        const vault = new KeepassVault('i/do/not/exist');

        expect(vault.securityConfig._presetName).to.equal('better');
        expect(vault.keyfilePath).to.be.undefined;
        expect(vault.path).to.equal('i/do/not/exist');
    });
});
