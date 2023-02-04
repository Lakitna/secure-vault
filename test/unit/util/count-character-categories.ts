import { expect } from 'chai';
import { countCharacterCategories } from '../../../src/util/count-character-categories';

const categories = [
    {
        description: 'lower-case alpha',
        value: 'abc',
    },
    {
        description: 'upper-case alpha',
        value: 'ABC',
    },
    {
        description: 'numeric',
        value: '012',
    },
    {
        description: 'special character',
        value: '!@#',
    },
];

describe('Count character categories', () => {
    it('returns 0 for an empty string', () => {
        const result = countCharacterCategories('');

        expect(result).to.equal(0);
    });

    for (const category of categories) {
        it(`returns 1 for an ${category.description} string`, () => {
            const result = countCharacterCategories(category.value + category.value);

            expect(result).to.equal(1);
        });
    }

    it('returns 2 for a string with 2 categories', () => {
        const result = countCharacterCategories(
            categories[0].value + categories[1].value + categories[0].value + categories[1].value
        );

        expect(result).to.equal(2);
    });

    it('returns 3 for a string with 3 categories', () => {
        const result = countCharacterCategories(
            categories[0].value +
                categories[1].value +
                categories[2].value +
                categories[0].value +
                categories[1].value +
                categories[2].value
        );

        expect(result).to.equal(3);
    });

    it('returns 4 for a string with 4 categories', () => {
        const result = countCharacterCategories(
            categories[0].value +
                categories[1].value +
                categories[2].value +
                categories[3].value +
                categories[0].value +
                categories[1].value +
                categories[2].value +
                categories[3].value
        );

        expect(result).to.equal(4);
    });
});
