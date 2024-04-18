import { expect } from 'chai';
import { FuseResult } from 'fuse.js';
import { SecretValue } from '../../../src/secret-value';
import { detectPartialStringMatch } from '../../../src/util/partial-string-match';

describe('Partial string matcher util', () => {
    it('matches a string with an exact SecretValue', async () => {
        const a = 'foobar';
        const b = new SecretValue<string>('string', 'foobar');

        const result = detectPartialStringMatch(a, b);

        expect(result).to.not.be.false;
        expect((result as FuseResult<string>).score).to.equal(0);
    });

    it('matches exact strings', async () => {
        const a = 'foobar';
        const b = 'foobar';

        const result = detectPartialStringMatch(a, b);

        expect(result).to.not.be.false;
        expect((result as FuseResult<string>).score).to.equal(0);
    });

    it('matches similar strings', async () => {
        const a = 'foobar';
        const b = 'foo-bar';

        const result = detectPartialStringMatch(a, b);

        expect(result).to.not.be.false;
        expect((result as FuseResult<string>).score).to.be.at.least(0);
    });

    it('does not match unrelated strings', async () => {
        const a = 'foobar';
        const b = 'lorumipsum';

        const result = detectPartialStringMatch(a, b);

        expect(result).to.be.false;
    });

    it('matches an exact substring', async () => {
        const a = 'Lorum ipsum dolor sit amet conscuer';
        const b = 'dolor sit';

        const result = detectPartialStringMatch(a, b);

        expect(result).to.not.be.false;
        expect((result as FuseResult<string>).score).to.equal(0);
    });

    it('matches a close substring', async () => {
        const a = 'Lorum ipsum dolor sit amet conscuer';
        const b = 'sit team';

        const result = detectPartialStringMatch(a, b);

        expect(result).to.not.be.false;
        expect((result as FuseResult<string>).score).to.be.at.least(0);
    });

    it('matches a 2 character substring', async () => {
        const a = 'Lorum ipsum dolor sit amet conscuer';
        const b = 'si';

        const result = detectPartialStringMatch(a, b);

        expect(result).to.not.be.false;
        expect((result as FuseResult<string>).score).to.be.at.least(0);
    });

    it('matches a 1 character substring', async () => {
        const a = 'Lorum ipsum dolor sit amet conscuer';
        const b = 's';

        const result = detectPartialStringMatch(a, b);

        expect(result).to.not.be.false;
        expect((result as FuseResult<string>).score).to.be.at.least(0);
    });

    it('matches same string in different case', async () => {
        const a = 'foobar';
        const b = 'FOOBAR';

        const result = detectPartialStringMatch(a, b);

        expect(result).to.not.be.false;
        expect((result as FuseResult<string>).score).to.be.at.least(0);
    });

    it('matches a not so close substring', async () => {
        const a = 'Lorum ipsum dolor sit';
        const b = 'W0WuM 1P5um D0W0w 517';

        const looseResult = detectPartialStringMatch(a, b, 'loose');
        const normalResult = detectPartialStringMatch(a, b, 'normal');
        const strictResult = detectPartialStringMatch(a, b, 'strict');

        expect(looseResult).to.not.be.false;
        expect(normalResult).to.not.be.false;
        expect(strictResult).to.not.be.false;

        expect((looseResult as FuseResult<string>).item).to.not.equal(
            (normalResult as FuseResult<string>).item
        );
        expect((normalResult as FuseResult<string>).item).to.not.equal(
            (strictResult as FuseResult<string>).item
        );
    });

    it('matches long string with short substring', async () => {
        const a = 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz';
        const b = 'hello there, general pqrst kenobi';

        const result = detectPartialStringMatch(a, b);

        expect(result).to.not.be.false;
        expect((result as FuseResult<string>).score).to.be.at.least(0);
    });
});
