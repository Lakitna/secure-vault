import { packageUp } from 'package-up';

/**
 * Find the package.json closest to the given path. If any.
 * @param dirPath Absolute path to a directory
 */
export async function getRoot(dirPath: string): Promise<false | string> {
    const p = await packageUp({
        cwd: dirPath,
    });
    return p === undefined ? false : p;
}

export default {
    getRoot,
};
