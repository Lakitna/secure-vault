import { describe } from 'vitest';

describe.todo('Security checker');

// import { expect } from 'chai';
// import { Rule, Rulebook, RuleError } from 'rulebound';
// import * as sinon from 'sinon';
// import { CredentialRuleError } from '../../../src/error/credential-error';
// import { VaultRuleError } from '../../../src/error/vault-error';
// import { SecurityChecker } from '../../../src/security-checker';
// import { Vault } from '../../../src/vault/vault';

// describe('Security checker', () => {
//     const mockVault = sinon.createStubInstance(Vault);

//     it('applies multiple credential rules', async () => {
//         const rulebookAddStub = sinon.stub(Rulebook.prototype, 'add');

//         new SecurityChecker();

//         expect(rulebookAddStub).to.have.been.called;
//         expect(rulebookAddStub.callCount).to.be.above(10);
//     });

//     context('checkCredentialSecurity', () => {
//         it('enforces with rulebound', async () => {
//             sinon.stub(Rulebook.prototype, 'add');
//             const rulebookEnfoceStub = sinon.stub(Rulebook.prototype, 'enforce').resolves();

//             const checker = new SecurityChecker();
//             await checker.checkCredentialSecurity(
//                 // @ts-expect-error Don't care about contents
//                 { config: true },
//                 { id: '1337' },
//                 mockVault
//             );

//             expect(rulebookEnfoceStub).to.have.been.calledOnce;
//             expect(rulebookEnfoceStub).to.have.been.calledWithExactly(
//                 // All rules
//                 '**/*',
//                 {
//                     config: { config: true },
//                     credential: { id: '1337' },
//                     vault: mockVault,
//                 }
//             );
//         });

//         it('throws a CredentialRuleError when a rule fails', async () => {
//             sinon.stub(Rulebook.prototype, 'add');
//             sinon
//                 .stub(Rulebook.prototype, 'enforce')
//                 .rejects(new RuleError(new Rule('amazing-rule'), 'oh no a fail'));

//             const checker = new SecurityChecker();
//             await expect(
//                 checker.checkCredentialSecurity(
//                     // @ts-expect-error Don't care about contents
//                     { config: true },
//                     { id: '1337' },
//                     mockVault
//                 )
//             ).to.be.rejectedWith(CredentialRuleError);
//         });
//     });

//     context('checkVaultSecurity', () => {
//         it('enforces with rulebound', async () => {
//             sinon.stub(Rulebook.prototype, 'add');
//             const rulebookEnfoceStub = sinon.stub(Rulebook.prototype, 'enforce').resolves();

//             const checker = new SecurityChecker();
//             await checker.checkVaultSecurity(
//                 'info',
//                 // @ts-expect-error Don't care about contents
//                 { config: true },
//                 mockVault,
//                 { vaultCredential: true }
//             );

//             expect(rulebookEnfoceStub).to.have.been.calledOnce;
//             expect(rulebookEnfoceStub).to.have.been.calledWithExactly(
//                 // All rules
//                 '**/*',
//                 {
//                     config: { config: true },
//                     vault: mockVault,
//                     vaultCredential: { vaultCredential: true },
//                 }
//             );
//         });

//         it('throws a VaultRuleError when a rule fails', async () => {
//             sinon.stub(Rulebook.prototype, 'add');
//             sinon
//                 .stub(Rulebook.prototype, 'enforce')
//                 .rejects(new RuleError(new Rule('amazing-rule'), 'oh no a fail'));

//             const checker = new SecurityChecker();
//             await expect(
//                 checker.checkVaultSecurity(
//                     'info',
//                     // @ts-expect-error Don't care about contents
//                     { config: true },
//                     mockVault,
//                     { vaultCredential: true }
//                 )
//             ).to.be.rejectedWith(VaultRuleError);
//         });
//     });
// });
