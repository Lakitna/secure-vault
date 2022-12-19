import { dirname } from 'path';
import git from './git';
import npm from './npm';

/**
 * Returns true if the file is tracked by git.
 *
 * If there is no git repo, will return true if the file is part of an NPM package.
 * @param filePath Absolute path to a file
 */
export async function fileWithCode(filePath: string): Promise<boolean> {
    const fileGitRoot = await git.getRoot(dirname(filePath));
    if (fileGitRoot !== false) {
        const gitignored = await git.isIgnored(filePath);
        if (gitignored) {
            // It's in the codebase, but not remote.
            return false;
        }

        const codeGitRoot = await git.getRoot(process.cwd());
        return fileGitRoot === codeGitRoot;
    }

    // We're not in a git repo, fall back to NPM project instead
    const fileNpmRoot = await npm.getRoot(dirname(filePath));
    if (fileNpmRoot !== false) {
        const codeNpmRoot = await npm.getRoot(process.cwd());
        return fileNpmRoot === codeNpmRoot;
    }

    return false;
}

export default {
    fileWithCode,
};
