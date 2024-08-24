import { describe, expect, it, vi } from 'vitest';
import { fileWithCode } from '../../../src/util/file-with-code.ts';
import git from '../../../src/util/git.ts';
import npm from '../../../src/util/npm.ts';

describe('File with code', () => {
    it('returns true when filepath in git repo', async () => {
        const gitGetRootStub = vi.spyOn(git, 'getRoot').mockResolvedValue('fale/git-repo/root');
        const gitIsIgnoredStub = vi.spyOn(git, 'isIgnored').mockResolvedValue(false);
        const npmGetRootStub = vi.spyOn(npm, 'getRoot');

        const result = await fileWithCode('my/amazing/directory/file-path.ext');

        expect(result).toEqual(true);
        expect(gitGetRootStub).toHaveBeenCalledWith('my/amazing/directory');
        expect(gitGetRootStub).toHaveBeenCalledWith(process.cwd());
        expect(gitIsIgnoredStub).toHaveBeenCalledWith('my/amazing/directory/file-path.ext');
        expect(npmGetRootStub).toHaveBeenCalledTimes(0);
    });

    it('returns false when in different git repos', async () => {
        const gitGetRootStub = vi
            .spyOn(git, 'getRoot')
            .mockResolvedValueOnce('fake/git-repo/root')
            .mockResolvedValue('another/fake/git-repo/root');
        const gitIsIgnoredStub = vi.spyOn(git, 'isIgnored').mockResolvedValue(false);
        const npmGetRootStub = vi.spyOn(npm, 'getRoot');

        const result = await fileWithCode('my/amazing/directory/file-path.ext');

        expect(result).to.be.false;
        expect(gitGetRootStub).toHaveBeenCalledWith('my/amazing/directory');
        expect(gitGetRootStub).toHaveBeenCalledWith(process.cwd());
        expect(gitIsIgnoredStub).toHaveBeenCalledWith('my/amazing/directory/file-path.ext');
        expect(npmGetRootStub).toHaveBeenCalledTimes(0);
    });

    it('returns true when filepath in npm project', async () => {
        const gitGetRootStub = vi.spyOn(git, 'getRoot').mockResolvedValue(false);
        const gitIsIgnoredStub = vi.spyOn(git, 'isIgnored');
        const npmGetRootStub = vi.spyOn(npm, 'getRoot').mockResolvedValue('fake/npm-project/root');

        const result = await fileWithCode('my/amazing/directory/file-path.ext');

        expect(result).to.be.true;
        expect(gitGetRootStub).toHaveBeenCalledWith('my/amazing/directory');
        expect(gitIsIgnoredStub).toHaveBeenCalledTimes(0);
        expect(npmGetRootStub).toHaveBeenCalledWith('my/amazing/directory');
        expect(npmGetRootStub).toHaveBeenCalledWith(process.cwd());
    });

    it('returns false when in different npm projects', async () => {
        const gitGetRootStub = vi.spyOn(git, 'getRoot').mockResolvedValue(false);
        const gitIsIgnoredStub = vi.spyOn(git, 'isIgnored');
        const npmGetRootStub = vi
            .spyOn(npm, 'getRoot')
            .mockResolvedValueOnce('fake/npm-project/root')
            .mockResolvedValue('another/fake/npm-project/root');

        const result = await fileWithCode('my/amazing/directory/file-path.ext');

        expect(result).to.be.false;
        expect(gitGetRootStub).toHaveBeenCalledWith('my/amazing/directory');
        expect(gitIsIgnoredStub).toHaveBeenCalledTimes(0);
        expect(npmGetRootStub).toHaveBeenCalledWith('my/amazing/directory');
        expect(npmGetRootStub).toHaveBeenCalledWith(process.cwd());
    });

    it('returns false when in git repo, but gitignored and not in npm project', async () => {
        const gitGetRootStub = vi.spyOn(git, 'getRoot').mockResolvedValue('fake/git-repo/root');
        const gitIsIgnoredStub = vi.spyOn(git, 'isIgnored').mockResolvedValue(true);
        const npmGetRootStub = vi.spyOn(npm, 'getRoot').mockResolvedValue(false);

        const result = await fileWithCode('my/amazing/directory/file-path.ext');

        expect(result).to.be.false;
        expect(gitGetRootStub).toHaveBeenCalledWith('my/amazing/directory');
        expect(gitIsIgnoredStub).toHaveBeenCalledWith('my/amazing/directory/file-path.ext');
        expect(npmGetRootStub).toHaveBeenCalledTimes(0);
    });

    it('returns false when not git repo, not in npm project', async () => {
        const gitGetRootStub = vi.spyOn(git, 'getRoot').mockResolvedValue(false);
        const gitIsIgnoredStub = vi.spyOn(git, 'isIgnored');
        const npmGetRootStub = vi.spyOn(npm, 'getRoot').mockResolvedValue(false);

        const result = await fileWithCode('my/amazing/directory/file-path.ext');

        expect(result).to.be.false;
        expect(gitGetRootStub).toHaveBeenCalledWith('my/amazing/directory');
        expect(gitIsIgnoredStub).toHaveBeenCalledTimes(0);
        expect(npmGetRootStub).toHaveBeenCalledWith('my/amazing/directory');
    });
});
