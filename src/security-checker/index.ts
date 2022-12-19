import { Kdbx } from 'kdbxweb';
import { Rulebook, RulebookConfig, RuleError } from 'rulebound';
import { ResolvedSecurityConfig } from '../config/security';
import { VaultCredential } from '../config/vault-password-prompt';
import { CredentialRuleError } from '../error/credential-error';
import { VaultRuleError } from '../error/vault-error';
import { KeepassCredential } from '../keepass/credential';
import { KeepassVault } from '../keepass/keepass-vault';

import { credentialAllowExpired } from './credential/credential-allow-expired';
import { credentialRequireExpiration } from './credential/credential-require-expiration';
import { credentialPasswordAge } from './credential/password/age';
import { credentialPasswordComplexityCharacterCategories } from './credential/password/complexity/character-categories';
import { credentialPasswordComplexityForbidReuse } from './credential/password/complexity/forbid-reuse';
import { credentialPasswordComplexityForbidUrl } from './credential/password/complexity/forbid-url';
import { credentialPasswordComplexityForbidUsername } from './credential/password/complexity/forbid-username';
import { credentialPasswordLength } from './credential/password/length';

import { vaultKeyfileRequire } from './vault/keyfile/keyfile-require';
import { vaultKeyfileStoredWithCode } from './vault/keyfile/keyfile-stored-with-code';
import { vaultPasswordAge } from './vault/password/age';
import { vaultPasswordComplexityCharacterCategories } from './vault/password/complexity/character-categories';
import { vaultPasswordComplexityCharacterForbidReuse } from './vault/password/complexity/forbid-reuse';
import { vaultPasswordComplexityCharacterForbidVaultName } from './vault/password/complexity/forbid-vault-name';
import { vaultPasswordComplexityCharacterForbidVaultPath } from './vault/password/complexity/forbid-vault-path';
import { vaultPasswordLength } from './vault/password/length';
import { vaultDecryptionTime } from './vault/vault-decryption-time';
import { vaultStoredWithCode } from './vault/vault-stored-with-code';
import { vaultStoredWithKeyfile } from './vault/vault-stored-with-keyfile';

export interface credentialRuleParameters {
    config: ResolvedSecurityConfig;
    vault: KeepassVault;
    credential: KeepassCredential;
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
    credential: KeepassCredential,
    vault: KeepassVault
): Promise<void> {
    const rulebook = await getCredentialRuleset({
        verboseness: vault.logLevel,
    });

    try {
        await rulebook.enforce('**/*', { config, credential, vault });
    } catch (err: unknown) {
        if (err instanceof RuleError) {
            throw new CredentialRuleError(credential, err);
        }
        throw err;
    }
}

export interface vaultRuleParameters {
    config: ResolvedSecurityConfig;
    vault: Kdbx;
    vaultCredential: VaultCredential;
}

let vaultRuleset: Rulebook<vaultRuleParameters>;
function getVaultRuleset(config: Partial<RulebookConfig>) {
    if (vaultRuleset) return vaultRuleset;

    const rules = new Rulebook<vaultRuleParameters>(config);

    rules.add(vaultDecryptionTime);
    rules.add(vaultKeyfileRequire);
    rules.add(vaultKeyfileStoredWithCode);
    rules.add(vaultPasswordAge);
    rules.add(vaultPasswordComplexityCharacterCategories);
    rules.add(vaultPasswordComplexityCharacterForbidReuse);
    rules.add(vaultPasswordComplexityCharacterForbidVaultName);
    rules.add(vaultPasswordComplexityCharacterForbidVaultPath);
    rules.add(vaultPasswordLength);
    rules.add(vaultStoredWithCode);
    rules.add(vaultStoredWithKeyfile);

    vaultRuleset = rules;
    return vaultRuleset;
}

export async function checkVaultSecurity(
    config: ResolvedSecurityConfig,
    vault: Kdbx,
    vaultCredential: VaultCredential
): Promise<void> {
    const rulebook = await getVaultRuleset({
        // verboseness: vault.logLevel,
    });

    try {
        await rulebook.enforce('**/*', { config, vault, vaultCredential });
    } catch (err) {
        if (err instanceof RuleError) {
            throw new VaultRuleError(vault, err);
        }
        throw err;
    }
}
