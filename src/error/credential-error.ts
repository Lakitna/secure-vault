import c from 'ansi-colors';
import { RuleError } from 'rulebound';
import { Credential } from '../credentials';

export class CredentialRuleError extends Error {
    credential: Pick<Credential, 'id' | 'path'>;
    rule: string;

    constructor(credential: Credential, ruleError: RuleError) {
        const description = ruleError.description ? '\n' + c.yellow(ruleError.description) : '';
        super(ruleError.message + description);

        this.credential = {
            id: credential.id,
            path: credential.path,
        };
        this.rule = ruleError.rule;
    }
}
