import { packageUp } from 'package-up';
import { describe, expect, it, MockedFunction, vi } from 'vitest';
import npm from '../../../src/util/npm.ts';

vi.mock('package-up', () => {
    return { packageUp: vi.fn() };
});
const packageUpMock = packageUp as MockedFunction<typeof packageUp>;

describe('NPM project utils', () => {
    it('returns the root folder if in an npm project', async () => {
        packageUpMock.mockResolvedValueOnce('some/directory/path');

        const result = await npm.getRoot('my/amazing/directory/path');

        expect(result).toEqual('some/directory/path');
        expect(packageUpMock).toHaveBeenCalledWith({
            cwd: 'my/amazing/directory/path',
        });
    });

    it('returns false if not in an npm project', async () => {
        packageUpMock.mockResolvedValueOnce(undefined);

        const result = await npm.getRoot('my/amazing/directory/path');

        expect(result).toEqual(false);
        expect(packageUpMock).toHaveBeenCalledWith({
            cwd: 'my/amazing/directory/path',
        });
    });
});
