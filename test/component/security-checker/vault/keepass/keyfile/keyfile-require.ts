import { expect } from 'chai';
import Rulebook, { Rule } from 'rulebound';
import * as sinon from 'sinon';
import { vaultRuleParameters } from '../../../../../../src/security-checker';
import { keepassVaultKeyfileRequire } from '../../../../../../src/security-checker/vault/keepass/keyfile/keyfile-require';
import { getBaseVault } from '../../../../support/base-vault';
import { vaultRuleParams } from '../../../../support/vault-rule-param';

describe('Vault security check: require keyfile', () => {
    const vault = getBaseVault();
    const rulebook = new Rulebook<vaultRuleParameters>();
    let rule: Rule<vaultRuleParameters>;

    beforeEach(() => {
        rule = keepassVaultKeyfileRequire();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    after(async () => {
        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.requireKeyfile = false;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).to.equal(1);

        const rule = rulebook.rules[0];
        expect(rule.description).to.be.a('string');
        expect(rule.description?.length).to.be.above(0);
    });

    it('throws when there is no keyfile', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.requireKeyfile = true;
        params.vaultCredential.multifactor = undefined;

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Vault requires keyfile as second authentication factor'
        );
    });

    it('does not throw when there is a keyfile', async () => {
        const params = await vaultRuleParams(vault);

        params.config.vaultRestrictions.requireKeyfile = true;
        params.vaultCredential.multifactor = 'path/to/keyfile';

        await rulebook.enforce(rule.name, params);
    });

    it('disables when a keyfile is not required', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await vaultRuleParams(vault);
        params.config.vaultRestrictions.requireKeyfile = false;
        params.vaultCredential.multifactor = undefined;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Disabled by security config `requireKeyfile`'
        );
    });
});
