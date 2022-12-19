export type securityVaultRestrictionPresetNames = keyof typeof securityVaultRestrictionPresets;

export interface SecurityVaultRestriction {
    _presetName?: string;
    /**
     * Minimum vault password length
     *
     * Character count between 0 and Infinity
     */
    minPasswordLength: number;
    /**
     * Maximum age of the vault password
     *
     * Hours between 0 and Infinity
     */
    maxPasswordAge: number;
    /**
     * Require a key file as second authentication factor
     */
    requireKeyfile: boolean;
    /**
     * Minimum time required to decrypt the vault
     *
     * Milliseconds between 100 and 10000
     */
    minDecryptionTime: number;
    /**
     * Allow the vault to be stored with code
     *
     * Assumes either Git repository or NPM project. If Git, it's fine if gitignored.
     */
    allowVaultWithCode: boolean;
    /**
     * Allow the keyfile to be stored with code
     *
     * Assume either Git repository or NPM project. If Git, it's fine if gitignored.
     *
     * Does nothing if no keyfile is present.
     */
    allowKeyfileWithCode: boolean;
    /**
     * Allow the vault and keyfile both in the same Git repository, NPM project, or directory.
     *
     * Does nothing if no keyfile is present.
     */
    allowVaultAndKeyfileSameLocation: boolean;
    /**
     * Password complexity restrictions
     */
    passwordComplexity: {
        /**
         * Minimum number of character categories
         *
         * Categories:
         * - Uppercase characters A-Z (Latin alphabet)
         * - Lowercase characters a-z (Latin alphabet)
         * - Digits 0-9
         * - Special characters (!, $, #, %, etc.)
         */
        minCharacterCategories: number;
        /**
         * Forbid the password from containing (part of) the vault name
         */
        forbidVaultName: boolean;
        /**
         * Forbid the password from containing (part of) the vault file path
         */
        forbidVaultPath: boolean;
        /**
         * Forbid the vault password from also being used by any credential
         */
        forbidReuse: boolean;
    };
    // Not tracked by keepass
    // maxKeyfileAge: number;
}

export const securityVaultRestrictionPresets = {
    none: {
        _presetName: 'none',
        minPasswordLength: 0,
        maxPasswordAge: Infinity,
        requireKeyfile: false,
        minDecryptionTime: 100,
        allowVaultWithCode: true,
        allowKeyfileWithCode: true,
        allowVaultAndKeyfileSameLocation: true,
        passwordComplexity: {
            minCharacterCategories: 1,
            forbidVaultName: false,
            forbidVaultPath: false,
            forbidReuse: false,
        },
    } as SecurityVaultRestriction,
    basic: {
        _presetName: 'basic',
        minPasswordLength: 10,
        maxPasswordAge: 17520, // 2 years
        requireKeyfile: false,
        minDecryptionTime: 400,
        allowVaultWithCode: true,
        allowKeyfileWithCode: true,
        allowVaultAndKeyfileSameLocation: false,
        passwordComplexity: {
            minCharacterCategories: 2,
            forbidVaultName: false,
            forbidVaultPath: false,
            forbidReuse: true,
        },
    } as SecurityVaultRestriction,
    good: {
        _presetName: 'good',
        minPasswordLength: 15,
        maxPasswordAge: 8760, // 1 year
        requireKeyfile: true,
        minDecryptionTime: 700,
        allowVaultWithCode: false,
        allowKeyfileWithCode: true,
        allowVaultAndKeyfileSameLocation: false,
        passwordComplexity: {
            minCharacterCategories: 3,
            forbidVaultName: true,
            forbidVaultPath: false,
            forbidReuse: true,
        },
    } as SecurityVaultRestriction,
    better: {
        _presetName: 'better',
        minPasswordLength: 30,
        maxPasswordAge: 2190, // 1 quarter
        requireKeyfile: true,
        minDecryptionTime: 2000,
        allowVaultWithCode: false,
        allowKeyfileWithCode: true,
        allowVaultAndKeyfileSameLocation: false,
        passwordComplexity: {
            minCharacterCategories: 3,
            forbidVaultName: true,
            forbidVaultPath: true,
            forbidReuse: true,
        },
    } as SecurityVaultRestriction,
} as const;
