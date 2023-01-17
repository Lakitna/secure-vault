import { expect } from 'chai';
import Rulebook, { Rule } from 'rulebound';
import * as sinon from 'sinon';
import { credentialRuleParameters } from '../../../../src/security-checker';
import { credentialRequireExpiration } from '../../../../src/security-checker/credential/credential-require-expiration';
import { getBaseVault } from '../../support/base-vault';
import { credentialRuleParam } from '../../support/credential-rule-param';

describe('Credential security check: credential require expiration', () => {
    const vault = getBaseVault();
    const rulebook = new Rulebook<credentialRuleParameters>();
    let rule: Rule<credentialRuleParameters>;

    beforeEach(() => {
        rule = credentialRequireExpiration();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    after(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.requireExpiration = false;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).to.equal(1);

        const rule = rulebook.rules[0];
        expect(rule.description).to.be.a('string');
        expect(rule.description?.length).to.be.above(0);
    });

    it('throws when the credential has no expiration date', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.requireExpiration = true;
        params.credential.hasExpiration = false;

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Credential has no exipiration date'
        );
    });

    it('does not throw when the credential has expiration date', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.requireExpiration = true;
        params.credential.hasExpiration = true;

        await rulebook.enforce(rule.name, params);
    });

    it('disables when no expiration date is required', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.requireExpiration = false;
        params.credential.hasExpiration = false;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Disabled by security config `requireExpiration`'
        );
    });
});
