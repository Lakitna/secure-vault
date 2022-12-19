import Fuse from 'fuse.js';
import memoize from 'micro-memoize';
import { SecretValue } from '../secret-value';

/**
 * Detect partial string matches.
 *
 * Not suited for long strings.
 */
export function detectPartialStringMatch(
    a: string | SecretValue<string>,
    b: string | SecretValue<string>,
    strictness: 'strict' | 'normal' | 'loose' = 'normal'
): false | Fuse.FuseResult<string> {
    const minSubstringLength = 5;
    const substringLengthStep = Math.floor(minSubstringLength / 2);
    let matchThreshold: number;
    switch (strictness) {
        case 'loose':
            matchThreshold = 0.4;
            break;
        case 'normal':
            matchThreshold = 0.3;
            break;
        case 'strict':
            matchThreshold = 0.2;
            break;
    }

    const aSubstrings = makePossibleSubstringsMemoized(a, minSubstringLength, substringLengthStep);
    const bSubstrings = makePossibleSubstringsMemoized(b, minSubstringLength, substringLengthStep);

    const matcher = new Fuse(aSubstrings, {
        includeScore: true,
        isCaseSensitive: false,
        threshold: matchThreshold,
        findAllMatches: false,
        includeMatches: false,
    });

    const match = bSubstrings.map((a) => matcher.search(a)).flat();
    if (match.length === 0) {
        return false;
    }

    return match.sort((a, b) => {
        if (a.score === undefined || b.score === undefined) return 0;

        if (a.score > b.score) return 1;
        if (a.score < b.score) return -1;
        return 0;
    })[0];
}

/**
 * Split up a string in many different ways
 *
 * @param fullString Can be string or SecretValue. SecretValue will be exposed.
 */
function makePossibleSubstrings(
    fullString: string | SecretValue<string>,
    minLength: number,
    lengthStep: number
): string[] {
    const exposedString = fullString instanceof SecretValue ? fullString.expose() : fullString;

    if (exposedString.length <= minLength) {
        return [exposedString];
    }

    const substrings: string[] = [];

    for (let length = minLength; length < exposedString.length; length += lengthStep) {
        for (let i = 0; i < exposedString.length - length; i++) {
            substrings.push(exposedString.slice(i, i + length));
        }
    }

    substrings.push(exposedString);
    return substrings;
}
const makePossibleSubstringsMemoized = memoize(makePossibleSubstrings, {
    maxSize: 3,
});
