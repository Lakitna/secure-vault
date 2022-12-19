import c from 'ansi-colors';
import { Kdbx } from 'kdbxweb';
import { RuleError } from 'rulebound';

export class VaultRuleError extends Error {
    vault: string;
    rule: string;

    constructor(vault: Kdbx, ruleError: RuleError) {
        const description = ruleError.description ? '\n' + c.yellow(ruleError.description) : '';
        super(ruleError.message + description);

        this.rule = ruleError.rule;
        this.vault = vault.meta.name ?? '???';
    }
}
