import { Rulebook, RulebookConfig, RuleError } from 'rulebound';
import { ResolvedSecurityConfig } from '../config/security';
import { BaseVaultCredential } from '../config/vault-password-prompt';
import { Credential } from '../credentials';
import { CredentialRuleError } from '../error/credential-error';
import { VaultRuleError } from '../error/vault-error';
import { KeepassVault } from '../vault/keepass/keepass-vault';

import { credentialAllowExpired } from './credential/credential-allow-expired';
import { credentialRequireExpiration } from './credential/credential-require-expiration';
import { credentialPasswordAge } from './credential/password/age';
import { credentialPasswordComplexityCharacterCategories } from './credential/password/complexity/character-categories';
import { credentialPasswordComplexityForbidReuse } from './credential/password/complexity/forbid-reuse';
import { credentialPasswordComplexityForbidUrl } from './credential/password/complexity/forbid-url';
import { credentialPasswordComplexityForbidUsername } from './credential/password/complexity/forbid-username';
import { credentialPasswordLength } from './credential/password/length';

import { Vault } from '../vault/vault';
import { keepassVaultKeyfileRequire } from './vault/keepass/keyfile/keyfile-require';
import { keepassVaultKeyfileStoredWithCode } from './vault/keepass/keyfile/keyfile-stored-with-code';
import { keepassVaultPasswordComplexityCharacterForbidVaultName } from './vault/keepass/password/forbid-vault-name';
import { keepassVaultPasswordComplexityCharacterForbidVaultPath } from './vault/keepass/password/forbid-vault-path';
import { keepassVaultDecryptionTime } from './vault/keepass/vault-decryption-time';
import { keepassVaultStoredWithCode } from './vault/keepass/vault-stored-with-code';
import { keepassVaultStoredWithKeyfile } from './vault/keepass/vault-stored-with-keyfile';
import { vaultPasswordAge } from './vault/password/age';
import { vaultPasswordComplexityCharacterCategories } from './vault/password/complexity/character-categories';
import { vaultPasswordComplexityCharacterForbidReuse } from './vault/password/complexity/forbid-reuse';
import { vaultPasswordLength } from './vault/password/length';

export interface credentialRuleParameters {
    config: ResolvedSecurityConfig;
    vault: KeepassVault;
    credential: Credential;
}

export interface vaultRuleParameters {
    config: ResolvedSecurityConfig;
    vault: Vault;
    vaultCredential: BaseVaultCredential;
}

export class SecurityChecker {
    rulesetCredential: Rulebook<credentialRuleParameters>;
    rulesetVault: Rulebook<vaultRuleParameters>;

    constructor() {
        this.rulesetCredential = this.buildCredentialRuleset({});
        this.rulesetVault = this.buildVaultRuleset({});
    }

    private buildCredentialRuleset(config: Partial<RulebookConfig>) {
        const ruleset = new Rulebook<credentialRuleParameters>(config);

        ruleset.add(credentialAllowExpired);
        ruleset.add(credentialPasswordAge);
        ruleset.add(credentialPasswordComplexityCharacterCategories);
        ruleset.add(credentialPasswordComplexityForbidUrl);
        ruleset.add(credentialPasswordComplexityForbidUsername);
        ruleset.add(credentialPasswordComplexityForbidReuse);
        ruleset.add(credentialPasswordLength);
        ruleset.add(credentialRequireExpiration);

        return ruleset;
    }

    private buildVaultRuleset(config: Partial<RulebookConfig>) {
        const ruleset = new Rulebook<vaultRuleParameters>(config);

        ruleset.add(vaultPasswordAge);
        ruleset.add(vaultPasswordComplexityCharacterCategories);
        ruleset.add(vaultPasswordComplexityCharacterForbidReuse);
        ruleset.add(vaultPasswordLength);

        ruleset.add(keepassVaultDecryptionTime);
        ruleset.add(keepassVaultKeyfileRequire);
        ruleset.add(keepassVaultKeyfileStoredWithCode);
        ruleset.add(keepassVaultPasswordComplexityCharacterForbidVaultName);
        ruleset.add(keepassVaultPasswordComplexityCharacterForbidVaultPath);
        ruleset.add(keepassVaultStoredWithCode);
        ruleset.add(keepassVaultStoredWithKeyfile);

        return ruleset;
    }

    async checkCredentialSecurity(
        config: ResolvedSecurityConfig,
        credential: Credential,
        vault: KeepassVault
    ): Promise<void> {
        this.rulesetCredential.config.set({ verboseness: vault.logLevel });

        try {
            await this.rulesetCredential.enforce('**/*', { config, credential, vault });
        } catch (error: unknown) {
            if (error instanceof RuleError) {
                throw new CredentialRuleError(credential, error);
            }
            throw new Error('Unexpected error type', { cause: error });
        }
    }

    async checkVaultSecurity(
        logLevel: RulebookConfig['verboseness'],
        config: ResolvedSecurityConfig,
        vault: Vault,
        vaultCredential: BaseVaultCredential
    ): Promise<void> {
        this.rulesetVault.config.set({ verboseness: logLevel });

        try {
            await this.rulesetVault.enforce('**/*', { config, vault, vaultCredential });
        } catch (error) {
            if (error instanceof RuleError) {
                throw new VaultRuleError(vault, error);
            }
            throw new Error('Unexpected error type', { cause: error });
        }
    }
}
