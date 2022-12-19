import { Rule } from 'rulebound';
import { credentialRuleParameters } from '../../..';
import { detectPartialStringMatch } from '../../../../util/partial-string-match';

export function credentialPasswordComplexityForbidUsername() {
    return new Rule<credentialRuleParameters>('credential/password/complexity/forbid-username')
        .describe(
            `
            Ensure that the credential password does not contain the username.

            Attackers often use social engineering tactics to break a password. A common thing that
            user do, is to include (part of) a non-secret — like the username — in their
            passwords so it's easier to remember. Unfortunately, that also makes the password
            easier to break.

            Detection is done with fuzzy matching.
            If the username is email-like, everything before the '@' symbol is considered to be the
            username.
            `
        )
        .enable(({ config, credential }) => {
            const forbidUsername = config.credentialRestrictions.passwordComplexity.forbidUsername;
            if (!forbidUsername) {
                return 'Disabled by security config `forbidUsername`';
            }

            const username = credential.data.username;
            if (username.length === 0) {
                return 'No username, nothing to check';
            }

            const password = credential.data.password;
            if (password.length === 0) {
                return 'No password, nothing to check';
            }

            return true;
        })
        .define(({ credential }) => {
            const password = credential.data.password;
            let username = credential.data.username;
            if (isEmailLike(username)) {
                // This is a pretty crude approach. It will, for example, not work well with
                // gmails `username+variant` mail addresses. KISS for now.
                username = username.split('@')[0];
            }

            const match = detectPartialStringMatch(password, username, 'strict');
            if (match) {
                throw new Error('Password contains (part of) username');
            }

            return true;
        });
}

function isEmailLike(input: string): boolean {
    const split = input.split('@');
    if (split.length !== 2) {
        return false;
    }

    if (split[0].length === 0) {
        return false;
    }

    if (!new RegExp(/\w\.\w/).test(split[1])) {
        return false;
    }

    return true;
}
