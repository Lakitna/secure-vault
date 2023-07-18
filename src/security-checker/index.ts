import { Kdbx } from 'kdbxweb';
import { Rulebook, RulebookConfig, RuleError } from 'rulebound';
import { ResolvedSecurityConfig } from '../config/security';
import { BaseVaultCredential } from '../config/vault-password-prompt';
import { Credential } from '../credentials';
import { CredentialRuleError } from '../error/credential-error';
import { VaultRuleError } from '../error/vault-error';
import { KeepassVault } from '../keepass/keepass-vault';

import { credentialAllowExpired } from './credential/credential-allow-expired';
import { credentialRequireExpiration } from './credential/credential-require-expiration';
import { credentialPasswordAge } from './credential/password/age';
import { credentialPasswordComplexityCharacterCategories } from './credential/password/complexity/character-categories';
import { credentialPasswordComplexityForbidReuse } from './credential/password/complexity/forbid-reuse';
import { credentialPasswordComplexityForbidUrl } from './credential/password/complexity/forbid-url';
import { credentialPasswordComplexityForbidUsername } from './credential/password/complexity/forbid-username';
import { credentialPasswordLength } from './credential/password/length';

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

let credentialRuleset: Rulebook<credentialRuleParameters>;
function getCredentialRuleset(config: Partial<RulebookConfig>) {
    if (credentialRuleset) return credentialRuleset;

    const rules = new Rulebook<credentialRuleParameters>(config);

    rules.add(credentialAllowExpired);
    rules.add(credentialPasswordAge);
    rules.add(credentialPasswordComplexityCharacterCategories);
    rules.add(credentialPasswordComplexityForbidUrl);
    rules.add(credentialPasswordComplexityForbidUsername);
    rules.add(credentialPasswordComplexityForbidReuse);
    rules.add(credentialPasswordLength);
    rules.add(credentialRequireExpiration);

    credentialRuleset = rules;
    return credentialRuleset;
}

export async function checkCredentialSecurity(
    config: ResolvedSecurityConfig,
    credential: Credential,
    vault: KeepassVault
): Promise<void> {
    const rulebook = await getCredentialRuleset({
        verboseness: vault.logLevel,
    });

    try {
        await rulebook.enforce('**/*', { config, credential, vault });
    } catch (error: unknown) {
        if (error instanceof RuleError) {
            throw new CredentialRuleError(credential, error);
        }
        throw new Error('Unexpected error type', { cause: error });
    }
}

export interface vaultRuleParameters {
    config: ResolvedSecurityConfig;
    vault: Kdbx;
    vaultCredential: BaseVaultCredential;
}

let vaultRuleset: Rulebook<vaultRuleParameters>;
function getVaultRuleset(config: Partial<RulebookConfig>) {
    if (vaultRuleset) return vaultRuleset;

    const rules = new Rulebook<vaultRuleParameters>(config);

    rules.add(vaultPasswordAge);
    rules.add(vaultPasswordComplexityCharacterCategories);
    rules.add(vaultPasswordComplexityCharacterForbidReuse);
    rules.add(vaultPasswordLength);

    rules.add(keepassVaultDecryptionTime);
    rules.add(keepassVaultKeyfileRequire);
    rules.add(keepassVaultKeyfileStoredWithCode);
    rules.add(keepassVaultPasswordComplexityCharacterForbidVaultName);
    rules.add(keepassVaultPasswordComplexityCharacterForbidVaultPath);
    rules.add(keepassVaultStoredWithCode);
    rules.add(keepassVaultStoredWithKeyfile);

    vaultRuleset = rules;
    return vaultRuleset;
}

export async function checkVaultSecurity(
    logLevel: RulebookConfig['verboseness'],
    config: ResolvedSecurityConfig,
    vault: Kdbx,
    vaultCredential: BaseVaultCredential
): Promise<void> {
    const rulebook = await getVaultRuleset({
        verboseness: logLevel,
    });

    try {
        await rulebook.enforce('**/*', { config, vault, vaultCredential });
    } catch (error) {
        if (error instanceof RuleError) {
            throw new VaultRuleError(vault, error);
        }
        throw new Error('Unexpected error type', { cause: error });
    }
}
