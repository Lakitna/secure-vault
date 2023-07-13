import { expect } from 'chai';
import { SecretValue } from '../../../src/secret-value';
import {
    forgetRememberedPassword,
    getRememberedPassword,
    rememberPassword,
} from '../../../src/util/remember-password';

describe('Remember password util', () => {
    it('stores and retrieves a secret string', async () => {
        const key = 'vault-path-or-some-other-unique-value';
        const input = new SecretValue<string>('string', 'foo-bar-baz');

        await rememberPassword(key, input);
        const retrieved = await getRememberedPassword(key);

        expect(retrieved).to.not.equal(null);
        expect(input.equals(retrieved as SecretValue<string>)).to.be.true;

        await forgetRememberedPassword(key);
        const retrievedAfterDelete = await getRememberedPassword(key);
        expect(retrievedAfterDelete).to.be.null;
    });
});
