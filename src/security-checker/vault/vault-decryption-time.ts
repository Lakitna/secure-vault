import { Rule } from 'rulebound';
import { vaultRuleParameters } from '..';

export function vaultDecryptionTime() {
    return new Rule<vaultRuleParameters>('vault/decryption-time')
        .describe(
            `
                Enforce a minimum time for opening the vault.

                When trying to crack a vault master password and/or keyfile, attackers will try a lot
                of different passwords. By making the decryption harder, and thus longer, we can make
                brute force attacks as well as more sophisticated attacks a lot less viable.
                `
        )
        .enable(({ config, vault }) => {
            const minDecryptionTime = config.vaultRestrictions.minDecryptionTime;
            if (minDecryptionTime < 0) {
                throw new TypeError('Configuration error: Min decryption time can not be below 0');
            }

            const decryptionTime = Number(
                vault.meta.customData.get('KPXC_DECRYPTION_TIME_PREFERENCE')?.value
            );
            if (Number.isNaN(decryptionTime)) {
                // It looks like it it's actually pretty likely. It feels like the feature/setting
                // has been bolted on after the fact. So if we can't find the setting, we warn.
                return 'Could not fetch decryption time from vault';
            }

            return true;
        })
        .define(({ config, vault }) => {
            const minDecryptionTime = config.vaultRestrictions.minDecryptionTime;
            const decryptionTime = Number(
                vault.meta.customData.get('KPXC_DECRYPTION_TIME_PREFERENCE')?.value
            );

            if (decryptionTime < minDecryptionTime) {
                throw new Error(
                    `Vault decryption time is too short. ` +
                        `Should be at least ${minDecryptionTime}ms.`
                );
            }
            return true;
        });
}
