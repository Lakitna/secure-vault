import { expect } from 'chai';
import Rulebook from 'rulebound';
import * as sinon from 'sinon';
import { credentialRuleParameters } from '../../../../../src/security-checker';
import { credentialPasswordAge } from '../../../../../src/security-checker/credential/password/age';
import { getBaseVault } from '../../../support/base-vault';
import { credentialRuleParam } from '../../../support/credential-rule-param';

describe('Credential security check: credential password age', () => {
    const vault = getBaseVault();
    const rule = credentialPasswordAge();
    const rulebook = new Rulebook<credentialRuleParameters>();
    rulebook.add(rule);

    after(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.maxPasswordAge = Infinity;
    });

    it('throws when the credential password is too old', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.maxPasswordAge = 10;
        params.credential.passwordAge = 20;

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            'Credential password is too old, change it'
        );
    });

    it('does not throw when the credential password not too old', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.maxPasswordAge = 10;
        params.credential.passwordAge = 5;

        await rulebook.enforce(rule.name, params);
    });

    it('disables when the config is 0', async () => {
        const rule = credentialPasswordAge();
        const rulebook = new Rulebook<credentialRuleParameters>();
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });
        rulebook.add(rule);

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = sinon.stub(rule._log, 'error');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.maxPasswordAge = 0;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogErrorStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Configuration error: Max password age can not be equal to or below 0'
        );
    });

    it('disables when the config is below 0', async () => {
        const rule = credentialPasswordAge();
        const rulebook = new Rulebook<credentialRuleParameters>();
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });
        rulebook.add(rule);

        // @ts-expect-error Accessing a private var
        const ruleLogErrorStub = sinon.stub(rule._log, 'error');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.maxPasswordAge = -5;

        await rulebook.enforce(rule.name, params);

        expect(ruleLogErrorStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Configuration error: Max password age can not be equal to or below 0'
        );
    });
});
