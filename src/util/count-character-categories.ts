export const characterCategories = [
    /**
     * Lowercase base Latin alphabet
     */
    new RegExp(/[a-z]/),
    /**
     * Uppercase base Latin alphabet
     */
    new RegExp(/[A-Z]/),
    /**
     * Number
     */
    new RegExp(/[0-9]/),
    /**
     * Crude match for symbols.
     *
     * Matches anything that is
     * - Not a number
     * - Not in the base Latin alphabet (upper- or lowercase)
     * - Not whitespace
     */
    new RegExp(/[^a-zA-Z\d\s]/),
] as const;

/**
 * Count the number of categories present in the input string
 *
 * Categories:
 * - Uppercase characters A-Z (Latin alphabet)
 * - Lowercase characters a-z (Latin alphabet)
 * - Digits 0-9
 * - Special characters (!, $, #, %, etc.)
 */
export function countCharacterCategories(input: string): number {
    let categoryCount = 0;
    for (const category of characterCategories) {
        if (category.test(input)) {
            categoryCount++;
        }
    }
    return categoryCount;
}
