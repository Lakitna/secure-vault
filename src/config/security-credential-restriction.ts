export type securityCredentialRestrictionPresetNames =
    keyof typeof securityCredentialRestrictionPresets;

export interface SecurityCredentialRestriction {
    _presetName?: string;
    /**
     * Minimum password length
     *
     * Character count between 0 and Infinity
     */
    minPasswordLength: number;
    /**
     * Require that credentials have an expiration date
     */
    requireExpiration: boolean;
    /**
     * Allow the use of expired passwords
     */
    allowExpired: boolean;
    /**
     * Maximum age of the credential password before it expires
     *
     * Hours between 0 and Infinity
     */
    maxPasswordAge: number;
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
         * Forbid the password from containing (part of) the username
         */
        forbidUsername: boolean;
        /**
         * Forbid the password from containing (part of) the URL
         */
        forbidUrl: boolean;
        /**
         * Forbid the password from also being used by another credential
         */
        forbidReuse: boolean;
    };
}

export const securityCredentialRestrictionPresets = {
    none: {
        _presetName: 'none',
        minPasswordLength: 0,
        requireExpiration: false,
        allowExpired: true,
        maxPasswordAge: Infinity,
        passwordComplexity: {
            minCharacterCategories: 1,
            forbidUsername: false,
            forbidUrl: false,
            forbidReuse: false,
        },
    } as SecurityCredentialRestriction,
    basic: {
        _presetName: 'basic',
        minPasswordLength: 10,
        requireExpiration: false,
        allowExpired: false,
        maxPasswordAge: 17520, // 2 years
        passwordComplexity: {
            minCharacterCategories: 2,
            forbidUsername: true,
            forbidUrl: false,
            forbidReuse: true,
        },
    } as SecurityCredentialRestriction,
    good: {
        _presetName: 'good',
        minPasswordLength: 15,
        requireExpiration: false,
        allowExpired: false,
        maxPasswordAge: 8760, // 1 year
        passwordComplexity: {
            minCharacterCategories: 3,
            forbidUsername: true,
            forbidUrl: true,
            forbidReuse: true,
        },
    } as SecurityCredentialRestriction,
    better: {
        _presetName: 'better',
        minPasswordLength: 30,
        requireExpiration: true,
        allowExpired: false,
        maxPasswordAge: 2190, // 1 quarter
        passwordComplexity: {
            minCharacterCategories: 3,
            forbidUsername: true,
            forbidUrl: true,
            forbidReuse: true,
        },
    } as SecurityCredentialRestriction,
} as const;
