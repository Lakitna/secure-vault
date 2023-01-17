import { expect } from 'chai';
import Rulebook, { Rule } from 'rulebound';
import * as sinon from 'sinon';
import { credentialRuleParameters } from '../../../../src/security-checker';
import { credentialAllowExpired } from '../../../../src/security-checker/credential/credential-allow-expired';
import { getBaseVault } from '../../support/base-vault';
import { credentialRuleParam } from '../../support/credential-rule-param';

describe('Credential security check: allow expired credential', () => {
    const vault = getBaseVault();
    const rulebook = new Rulebook<credentialRuleParameters>();
    let rule: Rule<credentialRuleParameters>;

    beforeEach(() => {
        rule = credentialAllowExpired();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    after(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.allowExpired = true;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).to.equal(1);

        const rule = rulebook.rules[0];
        expect(rule.description).to.be.a('string');
        expect(rule.description?.length).to.be.above(0);
    });

    it('throws when the credential is expired', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.allowExpired = false;
        params.credential.expired = true;

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith('Credential expired');
    });

    it('does not throw if the credential is not expired', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.allowExpired = false;
        params.credential.expired = false;

        await rulebook.enforce(rule.name, params);
    });

    it('disables if expired credentials are allowed', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.allowExpired = true;
        params.credential.expired = true;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Disabled by security config `allowExpired`'
        );
    });
});
