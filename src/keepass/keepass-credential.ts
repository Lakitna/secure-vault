import camelcase from 'camelcase';
import kdbxweb, { ProtectedValue } from 'kdbxweb';
import {
    Credential,
    CredentialData,
    CredentialDataWithoutSecrets,
    CredentialWithoutSecrets,
} from '../credentials';
import { SecretValue } from '../secret-value';

/**
 * Create a credentials object from a kdbx entry
 *
 * Will not include any secret values.
 */
export function createCredentialWithoutSecrets(
    kdbxEntry: kdbxweb.KdbxEntry
): CredentialWithoutSecrets {
    const data: Partial<CredentialDataWithoutSecrets> = {};
    for (const [key, val] of kdbxEntry.fields) {
        if (val instanceof kdbxweb.ProtectedValue) {
            continue;
        }

        if (key === 'Password') {
            // If the password is not set, it will have an unprotected value of ''
            // We never want to include password here.
            continue;
        }

        if (key === 'UserName') {
            // `UserName` is a super weird casing. We'll make it lowercase.
            data.username = val.toString();
        } else {
            data[camelcase(key)] = val.toString();
        }
    }

    const hasExpiration = kdbxEntry.times.expires === true;
    const now = new Date().getTime();
    const expired = (kdbxEntry.times.expiryTime?.getTime() ?? now) - now < 0;

    return {
        id: kdbxEntry.uuid.toString(),
        hasExpiration: hasExpiration,
        expired: hasExpiration && expired,
        passwordAge: getCredentialPasswordAge(kdbxEntry),
        data: data as CredentialDataWithoutSecrets,
        path: getEntryPath(kdbxEntry),
    };
}

function getEntryPath(entry: kdbxweb.KdbxEntry): string[] {
    function getParents(entry: kdbxweb.KdbxEntry | kdbxweb.KdbxGroup): kdbxweb.KdbxGroup[] {
        const parent = entry.parentGroup;
        if (parent === undefined) {
            return [];
        }

        return [...getParents(parent), parent];
    }

    const title = entry.fields.get('Title') as string;
    const parents = getParents(entry).map((parent) => {
        if (parent.name === undefined) return '?';
        return parent.name;
    });

    return [...parents, title];
}

/**
 * Create a credentials object from a kdbx entry
 */
export function createKeepassCredential(kdbxEntry: kdbxweb.KdbxEntry): Credential {
    const credentialWithoutSecrets = createCredentialWithoutSecrets(kdbxEntry);

    const data: Partial<CredentialData> = credentialWithoutSecrets.data;
    for (const [key, val] of kdbxEntry.fields) {
        if (val instanceof kdbxweb.ProtectedValue) {
            data[camelcase(key)] = new SecretValue('string', val);
        }
    }

    if (!(data.password instanceof SecretValue)) {
        // The password is not set. Let's keep our types clean
        data.password = new SecretValue('string', data.password ?? '');
    }

    const attachments: Credential['attachments'] = {};
    for (const [key, val] of kdbxEntry.binaries) {
        let binary = 'hash' in val ? val.value : val;
        if (binary instanceof ArrayBuffer) {
            binary = kdbxweb.ProtectedValue.fromBinary(binary);
        }

        attachments[key] = new SecretValue('binary', binary);
    }

    const cred: Credential = {
        ...credentialWithoutSecrets,
        data: data as CredentialData,
        attachments: attachments,
    };
    return cred;
}

/**
 * Crawl through the credential history to figure out how long ago the password was changed last
 * @returns Password age in hours
 */
function getCredentialPasswordAge(entry: kdbxweb.KdbxEntry): number {
    const currentPassword = entry.fields.get('Password') as ProtectedValue;

    let currentPasswordCreated = entry.times.lastModTime ?? new Date();
    const history = entry.history.sort((a, b) => {
        if (a.lastModTime > b.lastModTime) return -1;
        if (a.lastModTime < b.lastModTime) return 1;
        return 0;
    });
    for (const historyEntry of history) {
        const historyPassword = historyEntry.fields.get('Password') as ProtectedValue | string;
        if (typeof historyPassword === 'string') {
            continue;
        }

        if (currentPassword.getText() === historyPassword.getText()) {
            if (historyEntry.times.lastModTime) {
                currentPasswordCreated = historyEntry.times.lastModTime;
            }
            continue;
        }
        break;
    }

    const now = new Date();
    const hourInMilliseconds = 6000000;
    return (now.getTime() - currentPasswordCreated?.getTime()) / hourInMilliseconds;
}
