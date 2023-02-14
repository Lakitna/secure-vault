import kdbx from 'kdbxweb';
import util from 'node:util';

type secretValueTypes = string | Uint8Array;

export class SecretValue<T extends secretValueTypes> {
    value: kdbx.ProtectedValue;
    private type;

    /**
     * Wrapper for values you want to keep secret.
     *
     * This is an obfuscation layer that prevents you from accidentally leaking the secret. It
     * makes it harder to shoot yourself in your foot, but not impossible.
     */
    constructor(
        type: T extends string ? 'string' : T extends Uint8Array ? 'binary' : never,
        value:
            | kdbx.ProtectedValue
            | (T extends string ? string : T extends Uint8Array ? Uint8Array : never)
    ) {
        this.type = type;

        if (value instanceof kdbx.ProtectedValue) {
            this.value = value;
        } else {
            switch (this.type) {
                case 'string':
                    this.value = kdbx.ProtectedValue.fromString(value as string);
                    break;
                case 'binary':
                    this.value = kdbx.ProtectedValue.fromBinary(value as Uint8Array);
                    break;
                default:
                    throw new Error('Unexpected type ' + this.type);
            }
        }
    }

    /**
     * Thightly control which parts are exposed when inspecting or logging the secret value.
     */
    [util.inspect.custom]() {
        class SecretValue {
            value: string;
            type: string;

            constructor(type: string) {
                this.type = type;
                this.value = '[SECRET]';
            }
        }
        return new SecretValue(this.type);
    }

    /**
     * Expose the secret
     *
     * @returns the original secret
     */
    expose(): T {
        switch (this.type) {
            case 'string':
                return (this.value as kdbx.ProtectedValue).getText() as T;
            case 'binary':
                return this.value.getBinary() as T;
            default:
                throw new Error('Unexpected secret type');
        }
    }

    get length() {
        return this.value.byteLength;
    }

    /**
     * Check if two secrets are the same.
     *
     * Note: This will temporarily expose both secrets to allow full comparison
     */
    equals(other: SecretValue<secretValueTypes>): boolean {
        if (this.type !== other.type) {
            // Not the same type, so never the same.
            return false;
        }
        if (this.length !== other.length) {
            // Not the same length, so never the same.
            return false;
        }

        if (this.type === 'binary') {
            const thisBin = this.expose() as Uint8Array;
            const otherBin = other.expose() as Uint8Array;

            return thisBin.every((value, index) => value === otherBin[index]);
        }

        if (this.type === 'string') {
            return other.expose() === this.expose();
        }

        throw new Error('Unexpected secret type');
    }
}
