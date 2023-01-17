import { expect } from 'chai';
import Rulebook, { Rule } from 'rulebound';
import * as sinon from 'sinon';
import { SecretValue } from '../../../../../../src';
import { credentialRuleParameters } from '../../../../../../src/security-checker';
import { credentialPasswordComplexityForbidReuse } from '../../../../../../src/security-checker/credential/password/complexity/forbid-reuse';
import { getBaseVault } from '../../../../support/base-vault';
import { credentialRuleParam } from '../../../../support/credential-rule-param';

describe('Credential security check: credential password forbid reuse', () => {
    const vault = getBaseVault();
    const rulebook = new Rulebook<credentialRuleParameters>();
    let rule: Rule<credentialRuleParameters>;

    beforeEach(() => {
        rule = credentialPasswordComplexityForbidReuse();
        rulebook.add(rule);
    });

    afterEach(() => {
        rulebook.rules = [];
    });

    after(async () => {
        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidReuse = false;
    });

    it('has a description', async () => {
        expect(rulebook.rules.length).to.equal(1);

        const rule = rulebook.rules[0];
        expect(rule.description).to.be.a('string');
        expect(rule.description?.length).to.be.above(0);
    });

    it('throws when the password is reused', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidReuse = true;
        // The vault contains a credential with password 'lorum-ipsum'
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');

        await expect(rulebook.enforce(rule.name, params)).to.be.rejectedWith(
            `Credential password is used by another credential: 'Root/lorum'`
        );
    });

    it('disables when the config is false', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidReuse = false;
        params.credential.data.password = new SecretValue('string', 'lorum-ipsum');

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: Disabled by security config `forbidReuse`'
        );
    });

    it('does not throw when the password is unique', async () => {
        const params = await credentialRuleParam(vault);

        params.config.credentialRestrictions.passwordComplexity.forbidReuse = true;
        params.credential.data.password = new SecretValue('string', 'orum-ipsum');

        await rulebook.enforce(rule.name, params);
    });

    it('disables when the credential has no password', async () => {
        rule.on('enforce', () => {
            throw new Error('Should not be enforced');
        });

        // @ts-expect-error Accessing a private var
        const ruleLogDebugStub = sinon.stub(rule._log, 'debug');

        const params = await credentialRuleParam(vault);
        params.config.credentialRestrictions.passwordComplexity.forbidReuse = true;
        params.credential.data.password = new SecretValue('string', '');

        await rulebook.enforce(rule.name, params);

        expect(ruleLogDebugStub).to.have.been.calledOnceWithExactly(
            'Rule disabled: No password, nothing to check'
        );
    });
});
