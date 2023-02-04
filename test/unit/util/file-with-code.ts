import { expect } from 'chai';
import sinon from 'sinon';
import { fileWithCode } from '../../../src/util/file-with-code';
import git from '../../../src/util/git';
import npm from '../../../src/util/npm';

describe('File with code', () => {
    it('returns true when filepath in git repo', async () => {
        const gitGetRootStub = sinon.stub(git, 'getRoot').resolves('fake/git-repo/root');
        const gitIsIgnoredStub = sinon.stub(git, 'isIgnored').resolves(false);
        const npmGetRootStub = sinon.stub(npm, 'getRoot');

        const result = await fileWithCode('my/amazing/directory/file-path.ext');

        expect(result).to.be.true;
        expect(gitGetRootStub).to.have.been.calledWithExactly('my/amazing/directory');
        expect(gitGetRootStub).to.have.been.calledWithExactly(process.cwd());
        expect(gitIsIgnoredStub).to.have.been.calledOnceWithExactly(
            'my/amazing/directory/file-path.ext'
        );
        expect(npmGetRootStub).to.have.not.been.called;
    });

    it('returns false when in different git repos', async () => {
        const gitGetRootStub = sinon
            .stub(git, 'getRoot')
            .onFirstCall()
            .resolves('fake/git-repo/root')
            .onSecondCall()
            .resolves('another/fake/git-repo/root');
        const gitIsIgnoredStub = sinon.stub(git, 'isIgnored').resolves(false);
        const npmGetRootStub = sinon.stub(npm, 'getRoot');

        const result = await fileWithCode('my/amazing/directory/file-path.ext');

        expect(result).to.be.false;
        expect(gitGetRootStub).to.have.been.calledWithExactly('my/amazing/directory');
        expect(gitGetRootStub).to.have.been.calledWithExactly(process.cwd());
        expect(gitIsIgnoredStub).to.have.been.calledOnceWithExactly(
            'my/amazing/directory/file-path.ext'
        );
        expect(npmGetRootStub).to.have.not.been.called;
    });

    it('returns true when filepath in npm project', async () => {
        const gitGetRootStub = sinon.stub(git, 'getRoot').resolves(false);
        const gitIsIgnoredStub = sinon.stub(git, 'isIgnored');
        const npmGetRootStub = sinon.stub(npm, 'getRoot').resolves('fake/npm-project/root');

        const result = await fileWithCode('my/amazing/directory/file-path.ext');

        expect(result).to.be.true;
        expect(gitGetRootStub).to.have.been.calledOnceWithExactly('my/amazing/directory');
        expect(gitIsIgnoredStub).to.have.not.been.called;
        expect(npmGetRootStub).to.have.been.calledWithExactly('my/amazing/directory');
        expect(npmGetRootStub).to.have.been.calledWithExactly(process.cwd());
    });

    it('returns false when in different npm projects', async () => {
        const gitGetRootStub = sinon.stub(git, 'getRoot').resolves(false);
        const gitIsIgnoredStub = sinon.stub(git, 'isIgnored');
        const npmGetRootStub = sinon
            .stub(npm, 'getRoot')
            .onFirstCall()
            .resolves('fake/npm-project/root')
            .onSecondCall()
            .resolves('another/fake/npm-project/root');

        const result = await fileWithCode('my/amazing/directory/file-path.ext');

        expect(result).to.be.false;
        expect(gitGetRootStub).to.have.been.calledOnceWithExactly('my/amazing/directory');
        expect(gitIsIgnoredStub).to.have.not.been.called;
        expect(npmGetRootStub).to.have.been.calledWithExactly('my/amazing/directory');
        expect(npmGetRootStub).to.have.been.calledWithExactly(process.cwd());
    });

    it('returns false when in git repo, but gitignored and not in npm project', async () => {
        const gitGetRootStub = sinon.stub(git, 'getRoot').resolves('fake/git-repo/root');
        const gitIsIgnoredStub = sinon.stub(git, 'isIgnored').resolves(true);
        const npmGetRootStub = sinon.stub(npm, 'getRoot').resolves(false);

        const result = await fileWithCode('my/amazing/directory/file-path.ext');

        expect(result).to.be.false;
        expect(gitGetRootStub).to.have.been.calledOnceWithExactly('my/amazing/directory');
        expect(gitIsIgnoredStub).to.have.been.calledOnceWithExactly(
            'my/amazing/directory/file-path.ext'
        );
        expect(npmGetRootStub).to.have.not.been.called;
    });

    it('returns false when not git repo, not in npm project', async () => {
        const gitGetRootStub = sinon.stub(git, 'getRoot').resolves(false);
        const gitIsIgnoredStub = sinon.stub(git, 'isIgnored');
        const npmGetRootStub = sinon.stub(npm, 'getRoot').resolves(false);

        const result = await fileWithCode('my/amazing/directory/file-path.ext');

        expect(result).to.be.false;
        expect(gitGetRootStub).to.have.been.calledOnceWithExactly('my/amazing/directory');
        expect(gitIsIgnoredStub).to.have.not.been.called;
        expect(npmGetRootStub).to.have.been.calledOnceWithExactly('my/amazing/directory');
    });
});
