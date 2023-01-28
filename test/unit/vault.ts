import { expect } from 'chai';
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
});
