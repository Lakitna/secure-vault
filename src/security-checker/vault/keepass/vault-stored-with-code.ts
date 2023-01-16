import { Rule } from 'rulebound';
import { vaultRuleParameters } from '../..';
import file from '../../../util/file-with-code';
import { resolveSymlink } from '../../../util/resolve-symlink';

export function keepassVaultStoredWithCode() {
    return new Rule<vaultRuleParameters>('keepass/stored-with-code')
        .describe(
            `
            Vaults are often used for authenticating our application. We don't want to store our
            vault in the same place as our application code.

            If, for some reason, the source code leaks, we don't want potential attackers to also
            have access to our vault. We can somewhat mitigate this risk by storing the vault file
            separate from our code. This way, an attacker will have a harder time stealing our
            credentials.

            This rule ensures that the vault is not:
            1. In the same Git repository as the current working directory (unless it's gitignored)
            2. In the same NPM project as the current working directory

            Any symlinks are resolved recursively. Only the actual file path is used.
            `
        )
        .enable(async ({ config }) => {
            const allowVaultWithCode = config.vaultRestrictions.allowVaultWithCode;

            if (allowVaultWithCode === true) {
                return 'Disabled by security config `allowVaultWithCode`';
            }

            return true;
        })
        .define(async ({ vaultCredential }) => {
            const vaultPath = await resolveSymlink(vaultCredential.path);
            const vaultWithCode = await file.fileWithCode(vaultPath);
            return !vaultWithCode;
        })
        .punishment(() => {
            throw new Error('Vault is stored with source code');
        });
}
