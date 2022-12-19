import { expect } from 'chai';
import kdbxweb from 'kdbxweb';
import util from 'node:util';
import { SecretValue } from '../../src/index';

describe('Secret value', () => {
    it('stores a string as protected value and retrieves it as plaintext', () => {
        const input = 'Lorum ipsum';
        const secret = new SecretValue('string', input);

        expect(secret.value instanceof kdbxweb.ProtectedValue).to.be.true;
        expect(secret.expose()).to.equal(input);
    });

    it('stores a buffer as protected value and retrieves it as plaintext', () => {
        const input = Buffer.from('lorum ipsum');
        const secret = new SecretValue<Uint8Array>('binary', input);

        expect(secret.value instanceof kdbxweb.ProtectedValue).to.be.true;

        const exposed = secret.expose();
        expect(exposed instanceof Uint8Array).to.be.true;

        const decoder = new TextDecoder();
        expect(decoder.decode(exposed)).to.equal('lorum ipsum');
    });

    it('stores a protected value and retrieves it as plaintext', () => {
        const input = kdbxweb.ProtectedValue.fromString('lorum ipsum');
        const secret = new SecretValue('string', input);

        expect(secret.value instanceof kdbxweb.ProtectedValue).to.be.true;
        expect(secret.value).to.equal(input);

        expect(secret.expose()).to.equal('lorum ipsum');
    });

    it('get length of unexposed string value', () => {
        const input = 'Lorum ipsum';
        const secret = new SecretValue('string', input);

        expect(secret.length).to.equal(input.length);
    });

    it('get length of unexposed binary value', () => {
        const input = 'lorum ipsum';
        const secret = new SecretValue<Uint8Array>('binary', Buffer.from(input));

        expect(secret.length).to.equal(input.length);
    });

    it('constructor throws with unexpected type', () => {
        const input = 'lorum ipsum';

        expect(() => {
            // @ts-expect-error Deliberate error
            new SecretValue('not-supported', input);
        }).to.throw('Unexpected type not-supported');
    });

    it('expose throws with unexpected type', () => {
        const input = 'lorum ipsum';
        const secret = new SecretValue('string', input);

        // @ts-expect-error Deliberate error
        secret.type = 'not-supported';

        expect(() => {
            secret.expose();
        }).to.throw('Unexpected secret type');
    });

    it('does not expose a string when logged', () => {
        const input = 'lorum ipsum';
        const secret = new SecretValue('string', input);

        const inspected = util.inspect(secret);

        expect(inspected).to.not.contain(input);
        expect(inspected).to.contain('[SECRET]');
    });
});
