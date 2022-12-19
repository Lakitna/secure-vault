import { readlink } from 'node:fs/promises';

/**
 * Resolves the target of a symlink. If the target is not a symlink, will return the input
 * unchanged.
 *
 * Will resolve symlinks recursively.
 */
export async function resolveSymlink(path: string): Promise<string> {
    try {
        return resolveSymlink(await readlink(path));
    } catch {
        return path;
    }
}
