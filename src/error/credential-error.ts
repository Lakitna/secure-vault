import c from 'ansi-colors';
import { RuleError } from 'rulebound';
import { KeepassCredential } from '../keepass/credential';

export class CredentialRuleError extends Error {
    credential: Pick<KeepassCredential, 'id' | 'path'>;
    rule: string;

    constructor(credential: KeepassCredential, ruleError: RuleError) {
        const description = ruleError.description ? '\n' + c.yellow(ruleError.description) : '';
        super(ruleError.message + description);

        this.credential = {
            id: credential.id,
            path: credential.path,
        };
        this.rule = ruleError.rule;
    }
}
