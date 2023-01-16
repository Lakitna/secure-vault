import { Rule } from 'rulebound';
import { vaultRuleParameters } from '../../..';
import file from '../../../../util/file-with-code';
import { resolveSymlink } from '../../../../util/resolve-symlink';

export function keepassVaultKeyfileStoredWithCode() {
    return new Rule<vaultRuleParameters>('keepass/keyfile/stored-with-code')
        .describe(
            `
            The keyfile is used as a second authentication factor. We don't want to store our
            keyfile in the same place as our application code.

            If, for some reason, the source code leaks, we don't want potential attackers to also
            have access to our keyfile. We can reduce this risk by storing the keyfile separate
            from our code. This way, an attacker will have a harder time gaining access to the
            vault.

            This rule ensures that the keyfile is not:
            1. In the same Git repository as the current working directory (unless the vault is
                gitignored)
            2. In the same NPM project as the current working directory

            Any symlinks are resolved recursively. Only the actual file path is used.
            `
        )
        .enable(({ config, vaultCredential }) => {
            if (config.vaultRestrictions.allowKeyfileWithCode === true) {
                return 'Disabled by security config `allowKeyfileWithCode`';
            }

            if (!vaultCredential.keyfilePath) {
                // We check elsewhere if a keyfile is required.
                return 'No keyfile defined';
            }

            return true;
        })
        .define(async ({ vaultCredential }) => {
            const keyfilePath = await resolveSymlink(vaultCredential.keyfilePath as string);
            const keyfileWithCode = await file.fileWithCode(keyfilePath);
            return !keyfileWithCode;
        })
        .punishment(() => {
            throw new Error('Keyfile is stored with source code');
        });
}
