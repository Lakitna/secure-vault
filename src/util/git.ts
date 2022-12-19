import { exec } from 'child_process';
import { dirname } from 'path';

/**
 * Returns true if the file is ignored by git.
 *
 * Will not detect if git is not installed on the system.
 * @param path Aboslute path to a file
 */
export async function isIgnored(path: string): Promise<boolean> {
    return new Promise((resolve) => {
        exec(`git check-ignore "${path}"`, { cwd: dirname(path) }, (error) => {
            if (error) {
                resolve(false);
            } else {
                resolve(true);
            }
        });
    });
}

/**
 * Find the git root closest to the given path. If any.
 *
 * Will not detect if git is not installed on the system.
 * @param dirPath Absolute path to a directory
 */
export async function getRoot(dirPath: string): Promise<false | string> {
    return new Promise((resolve) => {
        exec('git rev-parse --show-toplevel', { cwd: dirPath }, (error, stdout) => {
            if (error) {
                resolve(false);
            } else {
                resolve(stdout.trim());
            }
        });
    });
}

export default {
    getRoot,
    isIgnored,
};
