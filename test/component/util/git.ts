import { expect } from 'chai';
import { exec } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { rimraf } from 'rimraf';
import { getRoot, isIgnored } from '../../../src/util/git';

describe('Git repo utils', () => {
    const gitRoot = path
        .join(path.dirname(fileURLToPath(import.meta.url)), '../support/tmpGit')
        .replaceAll('\\', '/');

    before(async () => {
        await fs.mkdir(gitRoot);
        await new Promise<void>((resolve, reject) => {
            exec('git init', { cwd: gitRoot }, (error) => {
                if (error) reject(error);
                resolve();
            });
        });
    });

    after(async () => {
        await rimraf(path.join(gitRoot));
    });

    describe('isIgnored', () => {
        before(async () => {
            await fs.writeFile(path.join(gitRoot, 'iAmIgnored.file'), '');
            await fs.writeFile(path.join(gitRoot, 'iAmNotIgnored.file'), '');
            await fs.writeFile(path.join(gitRoot, '.gitignore'), 'iAmIgnored.file');
        });

        it('return true when ignored', async () => {
            const result = await isIgnored(path.join(gitRoot, 'iAmIgnored.file'));

            expect(result).to.be.true;
        });

        it('return false when not ignored', async () => {
            const result = await isIgnored(path.join(gitRoot, 'iAmNotIgnored.file'));

            expect(result).to.be.false;
        });
    });

    describe('getRoot', () => {
        it('returns the root folder if given the root folder', async () => {
            const result = await getRoot(path.join(gitRoot));

            expect(result).to.equal(gitRoot);
        });

        it('returns the root folder if given a subfolder', async () => {
            const subfolderPath = path.join(gitRoot, 'something');
            await fs.mkdir(subfolderPath);

            const result = await getRoot(subfolderPath);

            expect(result).to.equal(gitRoot);
        });

        it('returns false if not in a git repository', async () => {
            const thisRepoRoot = await getRoot('');
            if (thisRepoRoot === false) {
                throw new Error('Could not find git root of this project');
            }
            const thisRepoParentDir = path.join(thisRepoRoot, '..');

            const result = await getRoot(thisRepoParentDir);

            expect(result).to.be.false;
        });
    });
});
