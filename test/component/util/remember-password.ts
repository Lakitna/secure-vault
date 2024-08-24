import { describe, expect, it } from 'vitest';
import { SecretValue } from '../../../src/secret-value.ts';
import {
    forgetRememberedPassword,
    getRememberedPassword,
    rememberPassword,
} from '../../../src/util/remember-password.ts';

describe('Remember password util', () => {
    it('stores and retrieves a secret string', async () => {
        const key = 'vault-path-or-some-other-unique-value';
        const input = new SecretValue<string>('string', 'foo-bar-baz');

        await rememberPassword(key, input);
        const retrieved = await getRememberedPassword(key);

        expect(retrieved).not.toEqual(null);
        expect(input.equals(retrieved as SecretValue<string>)).toEqual(true);

        await forgetRememberedPassword(key);
        const retrievedAfterDelete = await getRememberedPassword(key);
        expect(retrievedAfterDelete).toEqual(null);
    });
});
