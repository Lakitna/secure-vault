import { expect } from 'chai';
import esmock from 'esmock';
import sinon from 'sinon';

describe('NPM project utils', () => {
    it('returns the root folder if in an npm project', async () => {
        const pkgUpStub = sinon.stub().resolves('some/directory/path');
        const mockedModule = await esmock(
            '../../../src/util/npm.ts',
            import.meta.url,
            {
                'pkg-up': {
                    pkgUp: pkgUpStub,
                },
            },
            {}
        );

        const result = await mockedModule.getRoot('my/amazing/directory/path');

        expect(result).to.equal('some/directory/path');
        expect(pkgUpStub).to.have.been.calledOnceWithExactly({ cwd: 'my/amazing/directory/path' });
    });

    it('returns false if not in an npm project', async () => {
        const pkgUpStub = sinon.stub().resolves(undefined);
        const mockedModule = await esmock(
            '../../../src/util/npm.ts',
            import.meta.url,
            {
                'pkg-up': {
                    pkgUp: pkgUpStub,
                },
            },
            {}
        );

        const result = await mockedModule.getRoot('my/amazing/directory/path');

        expect(result).to.be.false;
        expect(pkgUpStub).to.have.been.calledOnceWithExactly({ cwd: 'my/amazing/directory/path' });
    });
});
