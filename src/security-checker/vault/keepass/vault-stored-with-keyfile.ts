import { dirname } from 'path';
import { Rule } from 'rulebound';
import { vaultRuleParameters } from '../..';
import git from '../../../util/git';
import npm from '../../../util/npm';
import { resolveSymlink } from '../../../util/resolve-symlink';

export function keepassVaultStoredWithKeyfile() {
    return new Rule<vaultRuleParameters>('keepass/stored-with-keyfile')
        .describe(
            `
            The keyfile is used as a second authentication factor. We don't want to store our
            keyfile in the same place as our vault.

            If, for some reason, the source code leaks, we don't want potential attackers to have
            access to both our vault and our keyfile. We can somewhat mitigate this risk by storing
            the vault and keyfile separate from each other. This way, an attacker will have a harder
            time stealing our credentials.

            This rule ensures that the vault and keyfile are not:
            1. In the same Git repository (unless one of them is gitignored)
            2. In the same NPM project
            3. In the same directory

            Any symlinks are resolved recursively. Only the actual file paths are used.
            `
        )
        .enable(async ({ config, vaultCredential }) => {
            const allowVaultAndKeyfileSameLocation =
                config.vaultRestrictions.allowVaultAndKeyfileSameLocation;
            if (allowVaultAndKeyfileSameLocation === true) {
                return 'Disabled by security config `allowVaultAndKeyfileSameLocation`';
            }

            if (!vaultCredential.multifactor) {
                // We check elsewhere if a keyfile is required.
                return 'No keyfile defined';
            }

            return true;
        })
        .define(async ({ vaultCredential }) => {
            const vaultPath = await resolveSymlink(vaultCredential.vaultPath);
            const keyfilePath = await resolveSymlink(vaultCredential.multifactor as string);

            const vaultGitRoot = await git.getRoot(dirname(vaultPath));
            const keyfileGitRoot = await git.getRoot(dirname(keyfilePath));
            const sameGit = vaultGitRoot !== false && vaultGitRoot === keyfileGitRoot;
            if (sameGit) {
                const vaultGitignored = await git.isIgnored(vaultPath);
                const keyfileGitignored = await git.isIgnored(keyfilePath);
                if (vaultGitignored || keyfileGitignored) {
                    // Vault and keyfile in the same repo, but not on remote.
                    return true;
                }

                throw new Error(
                    'Vault and keyfile are in the same Git repository @ ' + vaultGitRoot
                );
            }

            // The vault or keyfile are not in the same repo, or there is no repo. In any case, we'll fall
            // back to NPM project instead.
            const vaultNpmRoot = await npm.getRoot(dirname(vaultPath));
            const keyfileNpmRoot = await npm.getRoot(dirname(keyfilePath));
            const sameNpm = vaultNpmRoot !== false && vaultNpmRoot === keyfileNpmRoot;
            if (sameNpm) {
                throw new Error('Vault and keyfile are in the same NPM project @ ' + vaultNpmRoot);
            }

            // The vault and keyfile are not in the same repo or NPM project. Fall back to
            // checking if they're in the same folder.
            if (dirname(vaultPath) === dirname(keyfilePath)) {
                throw new Error(
                    'Vault and keyfile are in the same directory @ ' + dirname(vaultPath)
                );
            }

            return true;
        });
}
