import { RecursivePartial } from '../util/recursive-partial';
import {
    SecurityCredentialRestriction,
    securityCredentialRestrictionPresetNames,
    securityCredentialRestrictionPresets,
} from './security-credential-restriction';
import {
    SecurityVaultRestriction,
    securityVaultRestrictionPresetNames,
    securityVaultRestrictionPresets,
} from './security-vault-restriction';
import {
    userPasswordPrompt,
    vaultPasswordPromptPresetNames,
    vaultPasswordPromptPresets,
} from './vault-password-prompt';

export type securityConfigPresetNames = keyof typeof securityConfigPresets;

export interface SecurityConfig {
    _presetName?: string;
    /**
     * Security restrictions placed on the vault.
     */
    vaultRestrictions:
        | securityVaultRestrictionPresetNames
        | RecursivePartial<SecurityVaultRestriction>;
    /**
     * Security restrictions placed credentials in the vault.
     */
    credentialRestrictions:
        | securityCredentialRestrictionPresetNames
        | RecursivePartial<SecurityCredentialRestriction>;

    prompt: VaultPasswordPromptConfig;
}

export interface VaultPasswordPromptConfig {
    /**
     * Method for prompting the user for the vault master password.
     */
    method: vaultPasswordPromptPresetNames | userPasswordPrompt;
    /**
     * Allow the password to be saved in the operating systems credential manager.
     * Adds an option to the user prompt method where possible.
     */
    allowPasswordSave: boolean;
    /**
     * Default for password save option in the user prompt.
     */
    passwordSaveDefault: boolean;
}

export interface ResolvedSecurityConfig extends SecurityConfig {
    vaultRestrictions: SecurityVaultRestriction;
    credentialRestrictions: SecurityCredentialRestriction;
    prompt: VaultPasswordPromptConfig & { method: userPasswordPrompt };
}

export const securityConfigPresets = {
    none: {
        _presetName: 'none',
        vaultRestrictions: securityVaultRestrictionPresets.none,
        credentialRestrictions: securityCredentialRestrictionPresets.none,
        prompt: {
            method: vaultPasswordPromptPresets.cli,
            allowPasswordSave: true,
            passwordSaveDefault: true,
        },
        readonly: true,
    } as ResolvedSecurityConfig,
    basic: {
        _presetName: 'basic',
        vaultRestrictions: securityVaultRestrictionPresets.basic,
        credentialRestrictions: securityCredentialRestrictionPresets.basic,
        prompt: {
            method: vaultPasswordPromptPresets.popup,
            allowPasswordSave: true,
            passwordSaveDefault: false,
        },
        readonly: true,
    } as ResolvedSecurityConfig,
    good: {
        _presetName: 'good',
        vaultRestrictions: securityVaultRestrictionPresets.good,
        credentialRestrictions: securityCredentialRestrictionPresets.good,
        prompt: {
            method: vaultPasswordPromptPresets.popup,
            allowPasswordSave: false,
            passwordSaveDefault: false,
        },
        readonly: true,
    } as ResolvedSecurityConfig,
    better: {
        _presetName: 'better',
        vaultRestrictions: securityVaultRestrictionPresets.better,
        credentialRestrictions: securityCredentialRestrictionPresets.better,
        prompt: {
            method: vaultPasswordPromptPresets.popup,
            allowPasswordSave: false,
            passwordSaveDefault: false,
        },
        readonly: true,
    } as ResolvedSecurityConfig,
} as const;

/**
 * Resolve empty, full, partial, or preset security config.
 */
export function resolveSecurityConfig(
    input: securityConfigPresetNames | RecursivePartial<SecurityConfig> | undefined
): ResolvedSecurityConfig {
    const defaultConfig = securityConfigPresets.better;

    let securityConfig: SecurityConfig;
    if (input === undefined) {
        securityConfig = defaultConfig;
    } else if (typeof input === 'string') {
        securityConfig = securityConfigPresets[input];
    } else {
        securityConfig = Object.assign({}, defaultConfig, input);
        delete securityConfig._presetName;
    }

    if (typeof securityConfig.prompt.method === 'string') {
        securityConfig.prompt.method = vaultPasswordPromptPresets[securityConfig.prompt.method];
    }

    securityConfig.vaultRestrictions = resolveSecurityConfigVaultRestrictions(
        securityConfig.vaultRestrictions
    );
    securityConfig.credentialRestrictions = resolveSecurityConfigCredentialRestrictions(
        securityConfig.credentialRestrictions
    );

    return securityConfig as ResolvedSecurityConfig;
}

function resolveSecurityConfigVaultRestrictions(
    vaultRestrictions: SecurityConfig['vaultRestrictions']
): SecurityVaultRestriction {
    const defaultConfig = securityVaultRestrictionPresets.better;

    if (typeof vaultRestrictions === 'string') {
        return securityVaultRestrictionPresets[vaultRestrictions];
    }
    if (vaultRestrictions._presetName !== undefined) {
        return vaultRestrictions as SecurityVaultRestriction;
    }

    const output = Object.assign({}, defaultConfig, vaultRestrictions) as SecurityVaultRestriction;
    delete output._presetName;

    output.passwordComplexity = Object.assign(
        {},
        defaultConfig.passwordComplexity,
        vaultRestrictions.passwordComplexity
    );

    return output;
}

function resolveSecurityConfigCredentialRestrictions(
    credentialRestrictions: SecurityConfig['credentialRestrictions']
): SecurityCredentialRestriction {
    const defaultConfig = securityCredentialRestrictionPresets.better;

    if (typeof credentialRestrictions === 'string') {
        return securityCredentialRestrictionPresets[credentialRestrictions];
    }
    if (credentialRestrictions._presetName !== undefined) {
        return credentialRestrictions as SecurityCredentialRestriction;
    }

    const output = Object.assign(
        {},
        defaultConfig,
        credentialRestrictions
    ) as SecurityCredentialRestriction;
    delete output._presetName;

    output.passwordComplexity = Object.assign(
        {},
        defaultConfig.passwordComplexity,
        credentialRestrictions.passwordComplexity
    );

    return output;
}
