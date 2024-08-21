import c from 'ansi-colors';
import { RuleError } from 'rulebound';
import { EnforcableVault } from '../vault/enforcable.ts';

export class VaultRuleError extends Error {
    vault: string;
    rule: string;

    constructor(vault: EnforcableVault, ruleError: RuleError) {
        const description = ruleError.description ? '\n' + c.yellow(ruleError.description) : '';
        super(ruleError.message + description);

        this.rule = ruleError.rule;
        this.vault = vault.id ?? '???';
    }
}
