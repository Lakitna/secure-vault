import { Rule } from 'rulebound';
import { URL } from 'url';
import { credentialRuleParameters } from '../../..';
import { detectPartialStringMatch } from '../../../../util/partial-string-match';

export function credentialPasswordComplexityForbidUrl() {
    return new Rule<credentialRuleParameters>('credential/password/complexity/forbid-url')
        .describe(
            `
            Ensure that the credential password does not contain part of the websites domain (the
            first part of the URL).

            Attackers often use social engineering tactics to break a password. A common thing that
            user do, is to include (part of) a non-secret — like the login target — in their
            passwords so it's easier to remember. Unfortunately, that also makes the password
            easier to break.

            Detection is done with fuzzy matching.
            Only the domain and subdomains are considered.
            `
        )
        .enable(({ config, credential }) => {
            const forbidUrl = config.credentialRestrictions.passwordComplexity.forbidUrl;
            if (!forbidUrl) {
                return 'Disabled by security config `forbidUrl`';
            }

            const url = credential.data.url;
            if (url.length === 0) {
                return 'Credential has no URL';
            }

            const password = credential.data.password;
            if (password.length === 0) {
                return 'Credential has no password';
            }

            return true;
        })
        .define(({ credential }) => {
            const url = credential.data.url;
            const password = credential.data.password;

            const domainParts = urlDomains(url);
            for (const domainPart of domainParts) {
                if (domainPart.length <= 3) {
                    continue;
                }

                const match = detectPartialStringMatch(password, domainPart, 'strict');
                if (match) {
                    throw new Error('Password contains (part of) URL domain');
                }
            }

            return true;
        });
}

function urlDomains(input: string): string[] {
    const parsed = new URL(input);
    const host = parsed.hostname;

    if (new RegExp(/^(?:\d{1,3}\.){3}\d{1,3}$/).test(host)) {
        // It's an IP address
        return [host];
    }

    return host.split('.');
}
