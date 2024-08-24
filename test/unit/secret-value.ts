import kdbxweb from 'kdbxweb';
import util from 'node:util';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SecretValue } from '../../src/secret-value.ts';

describe('Secret value', () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('stores a string as protected value and retrieves it as plaintext', () => {
        const input = 'Lorum ipsum';
        const secret = new SecretValue('string', input);

        expect(secret.value instanceof kdbxweb.ProtectedValue).toEqual(true);
        expect(secret.expose()).toEqual(input);
    });

    it('stores a buffer as protected value and retrieves it as plaintext', () => {
        const input = Buffer.from('lorum ipsum');
        const secret = new SecretValue<Uint8Array>('binary', input);

        expect(secret.value instanceof kdbxweb.ProtectedValue).toEqual(true);

        const exposed = secret.expose();
        expect(exposed instanceof Uint8Array).toEqual(true);

        const decoder = new TextDecoder();
        expect(decoder.decode(exposed)).toEqual('lorum ipsum');
    });

    it('stores a protected value and retrieves it as plaintext', () => {
        const input = kdbxweb.ProtectedValue.fromString('lorum ipsum');
        const secret = new SecretValue('string', input);

        expect(secret.value instanceof kdbxweb.ProtectedValue).toEqual(true);
        expect(secret.value).toEqual(input);

        expect(secret.expose()).toEqual('lorum ipsum');
    });

    it('get length of unexposed string value', () => {
        const input = 'Lorum ipsum';
        const secret = new SecretValue('string', input);

        expect(secret.length).toEqual(input.length);
    });

    it('get length of unexposed binary value', () => {
        const input = 'lorum ipsum';
        const secret = new SecretValue<Uint8Array>('binary', Buffer.from(input));

        expect(secret.length).toEqual(input.length);
    });

    it('constructor throws with unexpected type', () => {
        const input = 'lorum ipsum';

        expect(() => {
            // @ts-expect-error Deliberate error
            new SecretValue('not-supported', input);
        }).toThrow('Unexpected type not-supported');
    });

    it('expose throws with unexpected type', () => {
        const input = 'lorum ipsum';
        const secret = new SecretValue('string', input);

        // @ts-expect-error Deliberate error
        secret.type = 'not-supported';

        expect(() => {
            secret.expose();
        }).toThrow('Unexpected secret type');
    });

    it('does not expose a string when logged', () => {
        const input = 'lorum ipsum';
        const secret = new SecretValue('string', input);

        const inspected = util.inspect(secret);

        expect(inspected).not.toContain(input);
        expect(inspected).toContain('[SECRET]');
    });

    describe('equals', () => {
        it('does not expose secrets when different types', () => {
            const a = new SecretValue('string', '123');
            const b = new SecretValue('binary', new Uint8Array([1, 2, 3]));

            const aExposeSpy = vi.spyOn(a, 'expose');
            const bExposeSpy = vi.spyOn(b, 'expose');

            const result = a.equals(b);

            expect(result).toBe(false);
            expect(aExposeSpy).toHaveBeenCalledTimes(0);
            expect(bExposeSpy).toHaveBeenCalledTimes(0);
        });

        describe('Both type string', () => {
            it('does not expose secrets when different length', () => {
                const a = new SecretValue<string>('string', '123');
                const b = new SecretValue<string>('string', '12345');

                const aExposeSpy = vi.spyOn(a, 'expose');
                const bExposeSpy = vi.spyOn(b, 'expose');

                const result = a.equals(b);

                expect(result).toBe(false);
                expect(aExposeSpy).toHaveBeenCalledTimes(0);
                expect(bExposeSpy).toHaveBeenCalledTimes(0);
            });

            it('exposes secrets to compare different strings of same length', () => {
                const a = new SecretValue<string>('string', '123');
                const b = new SecretValue<string>('string', '124');

                const aExposeSpy = vi.spyOn(a, 'expose');
                const bExposeSpy = vi.spyOn(b, 'expose');

                const result = a.equals(b);

                expect(result).toBe(false);
                expect(aExposeSpy).toHaveBeenCalledWith();
                expect(bExposeSpy).toHaveBeenCalledWith();
            });

            it('exposes secrets to compare equal strings', () => {
                const a = new SecretValue<string>('string', '123');
                const b = new SecretValue<string>('string', '123');

                const aExposeSpy = vi.spyOn(a, 'expose');
                const bExposeSpy = vi.spyOn(b, 'expose');

                const result = a.equals(b);

                expect(result).toBe(true);
                expect(aExposeSpy).toHaveBeenCalledWith();
                expect(bExposeSpy).toHaveBeenCalledWith();
            });
        });

        describe('Both type binary', () => {
            it('does not expose secrets when different length', () => {
                const a = new SecretValue<Uint8Array>('binary', new Uint8Array([1, 2, 3]));
                const b = new SecretValue<Uint8Array>('binary', new Uint8Array([1, 2, 3, 4, 5]));

                const aExposeSpy = vi.spyOn(a, 'expose');
                const bExposeSpy = vi.spyOn(b, 'expose');

                const result = a.equals(b);

                expect(result).toBe(false);
                expect(aExposeSpy).toHaveBeenCalledTimes(0);
                expect(bExposeSpy).toHaveBeenCalledTimes(0);
            });

            it('exposes secrets to compare different binaries of same length', () => {
                const a = new SecretValue<Uint8Array>('binary', new Uint8Array([1, 2, 3]));
                const b = new SecretValue<Uint8Array>('binary', new Uint8Array([1, 2, 4]));

                const aExposeSpy = vi.spyOn(a, 'expose');
                const bExposeSpy = vi.spyOn(b, 'expose');

                const result = a.equals(b);

                expect(result).toBe(false);
                expect(aExposeSpy).toHaveBeenCalledWith();
                expect(bExposeSpy).toHaveBeenCalledWith();
            });

            it('exposes secrets to compare equal binaries', () => {
                const a = new SecretValue<Uint8Array>('binary', new Uint8Array([1, 2, 3]));
                const b = new SecretValue<Uint8Array>('binary', new Uint8Array([1, 2, 3]));

                const aExposeSpy = vi.spyOn(a, 'expose');
                const bExposeSpy = vi.spyOn(b, 'expose');

                const result = a.equals(b);

                expect(result).toBe(true);
                expect(aExposeSpy).toHaveBeenCalledWith();
                expect(bExposeSpy).toHaveBeenCalledWith();
            });
        });
    });
});
