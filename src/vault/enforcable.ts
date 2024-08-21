import Rulebook, { RulebookConfig, RuleError } from 'rulebound';
import {
    ResolvedSecurityConfig,
    resolveSecurityConfig,
    SecurityConfig,
    securityConfigPresetNames,
} from '../config/security.ts';
import { BaseVaultCredential } from '../config/vault-password-prompt.ts';
import { Credential } from '../credentials.ts';
import { CredentialRuleError } from '../error/credential-error.ts';
import { VaultRuleError } from '../error/vault-error.ts';
import { credentialAllowExpired } from '../rules/credential/credential-allow-expired.ts';
import { credentialRequireExpiration } from '../rules/credential/credential-require-expiration.ts';
import { credentialPasswordAge } from '../rules/credential/password/age.ts';
import { credentialPasswordComplexityCharacterCategories } from '../rules/credential/password/complexity/character-categories.ts';
import { credentialPasswordComplexityForbidReuse } from '../rules/credential/password/complexity/forbid-reuse.ts';
import { credentialPasswordComplexityForbidUrl } from '../rules/credential/password/complexity/forbid-url.ts';
import { credentialPasswordComplexityForbidUsername } from '../rules/credential/password/complexity/forbid-username.ts';
import { credentialPasswordLength } from '../rules/credential/password/length.ts';
import { vaultPasswordAge } from '../rules/vault/password/age.ts';
import { vaultPasswordComplexityCharacterCategories } from '../rules/vault/password/complexity/character-categories.ts';
import { vaultPasswordComplexityCharacterForbidReuse } from '../rules/vault/password/complexity/forbid-reuse.ts';
import { vaultPasswordLength } from '../rules/vault/password/length.ts';
import { SecretValue } from '../secret-value.ts';
import type { ReadableVault } from './readable.ts';
import { BaseVault, BaseVaultOptions } from './vault.ts';

export interface VaultRules<VP = VaultRuleParameters> {
    vault: Rulebook<VP>;
    credential: Rulebook<CredentialRuleParameters>;
}

export interface VaultRuleParameters {
    config: ResolvedSecurityConfig;
    vault: EnforcableVault;
    vaultCredential: BaseVaultCredential;
}

export interface CredentialRuleParameters {
    config: ResolvedSecurityConfig;
    vault: ReadableVault;
    credential: Credential;
}

export interface EnforcableVaultOptions extends BaseVaultOptions {
    /**
     * @default 'info'
     */
    logLevel: RulebookConfig['verboseness'];
    securityConfig: securityConfigPresetNames | Partial<SecurityConfig>;
}

export abstract class EnforcableVault extends BaseVault {
    public enforcable = true;

    /**
     * Log level used when enforcing rules.
     */
    public logLevel: EnforcableVaultOptions['logLevel'];
    public securityConfig: ResolvedSecurityConfig;

    private _rules: VaultRules | null = null;

    constructor(options: Partial<EnforcableVaultOptions> = {}) {
        super(options);
        this.logLevel = options?.logLevel ?? 'info';
        this.securityConfig = resolveSecurityConfig(options.securityConfig);
    }

    /**
     * Returns when the vault password was last changed. Used to enforce vault rules.
     *
     * The rule will throw if `null` is returned
     */
    public abstract getVaultPasswordLastChangeDate(): Promise<Date | null>;

    /**
     * Returns the number of times the given password is used in the vault.
     */
    public abstract getPasswordUseCount(password: SecretValue<string>): Promise<number>;

    /**
     * @returns the full ruleset
     */
    public getVaultRules() {
        if (this._rules !== null) {
            return this._rules;
        }
        this._rules = getDefaultRules();
        this._rules = this.extendVaultRules(this._rules);
        return this._rules;
    }

    /**
     * Add vault-specific rules to the ruleset.
     */
    public extendVaultRules(rules: VaultRules) {
        return rules;
    }

    public async enforceVaultRules(vaultParameters: VaultRuleParameters) {
        const rules = this.getVaultRules();
        rules.vault.config.set({ verboseness: this.logLevel });

        try {
            await rules.vault.enforce('**/*', vaultParameters);
        } catch (error) {
            if (error instanceof RuleError) {
                throw new VaultRuleError(vaultParameters.vault, error);
            }
            throw new Error('Unexpected error type', { cause: error });
        }
    }

    public async enforceCredentialRules(credentialParameters: CredentialRuleParameters) {
        const rules = this.getVaultRules();
        rules.credential.config.set({ verboseness: this.logLevel });

        try {
            await rules.credential.enforce('**/*', credentialParameters);
        } catch (error: unknown) {
            if (error instanceof RuleError) {
                throw new CredentialRuleError(credentialParameters.credential, error);
            }
            throw new Error('Unexpected error type', { cause: error });
        }
    }
}

function getDefaultRules(ruleConfig: Partial<RulebookConfig> = {}) {
    const rules: VaultRules = {
        vault: new Rulebook<VaultRuleParameters>(ruleConfig),
        credential: new Rulebook<CredentialRuleParameters>(ruleConfig),
    };

    rules.vault.add(vaultPasswordAge);
    rules.vault.add(vaultPasswordComplexityCharacterCategories);
    rules.vault.add(vaultPasswordComplexityCharacterForbidReuse);
    rules.vault.add(vaultPasswordLength);

    rules.credential.add(credentialAllowExpired);
    rules.credential.add(credentialPasswordAge);
    rules.credential.add(credentialPasswordComplexityCharacterCategories);
    rules.credential.add(credentialPasswordComplexityForbidUrl);
    rules.credential.add(credentialPasswordComplexityForbidUsername);
    rules.credential.add(credentialPasswordComplexityForbidReuse);
    rules.credential.add(credentialPasswordLength);
    rules.credential.add(credentialRequireExpiration);

    return rules;
}
