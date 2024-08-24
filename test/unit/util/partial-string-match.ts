import { FuseResult } from 'fuse.js';
import { describe, expect, it } from 'vitest';
import { SecretValue } from '../../../src/secret-value.ts';
import { detectPartialStringMatch } from '../../../src/util/partial-string-match.ts';

describe('Partial string matcher util', () => {
    it('matches a string with an exact SecretValue', async () => {
        const a = 'foobar';
        const b = new SecretValue<string>('string', 'foobar');

        const result = detectPartialStringMatch(a, b);

        expect(result).not.toEqual(false);
        expect((result as FuseResult<string>).score).toEqual(0);
    });

    it('matches exact strings', async () => {
        const a = 'foobar';
        const b = 'foobar';

        const result = detectPartialStringMatch(a, b);

        expect(result).not.toEqual(false);
        expect((result as FuseResult<string>).score).toEqual(0);
    });

    it('matches similar strings', async () => {
        const a = 'foobar';
        const b = 'foo-bar';

        const result = detectPartialStringMatch(a, b);

        expect(result).not.toEqual(false);
        expect((result as FuseResult<string>).score).toBeGreaterThanOrEqual(0);
    });

    it('does not match unrelated strings', async () => {
        const a = 'foobar';
        const b = 'lorumipsum';

        const result = detectPartialStringMatch(a, b);

        expect(result).toEqual(false);
    });

    it('matches an exact substring', async () => {
        const a = 'Lorum ipsum dolor sit amet conscuer';
        const b = 'dolor sit';

        const result = detectPartialStringMatch(a, b);

        expect(result).not.toEqual(false);
        expect((result as FuseResult<string>).score).toEqual(0);
    });

    it('matches a close substring', async () => {
        const a = 'Lorum ipsum dolor sit amet conscuer';
        const b = 'sit team';

        const result = detectPartialStringMatch(a, b);

        expect(result).not.toEqual(false);
        expect((result as FuseResult<string>).score).toBeGreaterThanOrEqual(0);
    });

    it('matches a 2 character substring', async () => {
        const a = 'Lorum ipsum dolor sit amet conscuer';
        const b = 'si';

        const result = detectPartialStringMatch(a, b);

        expect(result).not.toEqual(false);
        expect((result as FuseResult<string>).score).toBeGreaterThanOrEqual(0);
    });

    it('matches a 1 character substring', async () => {
        const a = 'Lorum ipsum dolor sit amet conscuer';
        const b = 's';

        const result = detectPartialStringMatch(a, b);

        expect(result).not.toEqual(false);
        expect((result as FuseResult<string>).score).toBeGreaterThanOrEqual(0);
    });

    it('matches same string in different case', async () => {
        const a = 'foobar';
        const b = 'FOOBAR';

        const result = detectPartialStringMatch(a, b);

        expect(result).not.toEqual(false);
        expect((result as FuseResult<string>).score).toBeGreaterThanOrEqual(0);
    });

    it('matches a not so close substring', async () => {
        const a = 'Lorum ipsum dolor sit';
        const b = 'W0WuM 1P5um D0W0w 517';

        const looseResult = detectPartialStringMatch(a, b, 'loose');
        const normalResult = detectPartialStringMatch(a, b, 'normal');
        const strictResult = detectPartialStringMatch(a, b, 'strict');

        expect(looseResult).not.toEqual(false);
        expect(normalResult).not.toEqual(false);
        expect(strictResult).not.toEqual(false);

        expect((looseResult as FuseResult<string>).item).not.toEqual(
            (normalResult as FuseResult<string>).item
        );
        expect((normalResult as FuseResult<string>).item).not.toEqual(
            (strictResult as FuseResult<string>).item
        );
    });

    it('matches long string with short substring', async () => {
        const a = 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz';
        const b = 'hello there, general pqrst kenobi';

        const result = detectPartialStringMatch(a, b);

        expect(result).not.toEqual(false);
        expect((result as FuseResult<string>).score).toBeGreaterThanOrEqual(0);
    });
});
