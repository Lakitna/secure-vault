export {
    SecurityConfig,
    securityConfigPresetNames,
    securityConfigPresets,
} from './config/security';
export { Credential, CredentialWithoutSecrets } from './credentials';
export { KeepassVault } from './keepass/keepass-vault';
export { SecretValue } from './secret-value';

// const vault = new BitwardenVault()

const vault = new KeepassVault('C:/code/secure-vault/ijo-wms-test-users.kdbx', {
    keyfilePath: 'C:/code/secure-vault/keyfile.tmp.keyx',
    readonly: true,
    logLevel: 'info',
    securityConfig: 'none',
    // securityConfig: {
    //     vaultRestrictions: {
    //         minPasswordLength: 1000,
    //         //         // requireKeyfile: false,
    //         //         minDecryptionTime: 100,
    //         //         // maxPasswordAge: 10000, // in hours
    //         //         allowVaultWithCode: true,
    //         //         // allowKeyfileWithCode: true,
    //         //         // allowVaultAndKeyfileSameLocation: true,
    //         //         passwordComplexity: {
    //         //             minCharacterCategories: 1,
    //         //             //     forbidVaultName: true,
    //         //             //     forbidVaultPath: true,
    //         //             // forbidReuse: true,
    //         //         },
    //     },
    //     //     credentialRestrictions: {
    //     //         minPasswordLength: 20,
    //     //         //     requireExpiration: true,
    //     //         //     allowExpired: true,
    //     //         //     maxPasswordAge: 500, // in hours
    //     //         passwordComplexity: {
    //     //             // minCharacterCategories: 1,
    //     //             // forbidUsername: true,
    //     //             // forbidUrl: true,
    //     //             forbidReuse: false,
    //     //         },
    //     //     },
    //     //     // passwordPromptMethod: 'cli',
    //     allowPasswordSave: true,
    //     //     // passwordSaveDefault: false,
    // },
});

await vault.open();
// const list = await vault.listCredentials('there');
// console.log(list);
const cred = await vault.getCredential('Functional Users', 'Warehouse: Employee 1');
console.log(cred);

// if (cred) {
//     await vault.updateCredential(cred, {
//         data: {
//             notes: 'Hello',
//             title: 'Warehouse: Employee 1',
//             url: 'http://sudomain.sub.domain.tl/some/path',
//             username: 'wh_test1',
//             password: new SecretValue('string', 'new password'),
//             something: 'value',
//         },
//         attachments: {
//             foo: new SecretValue('binary', new Uint8Array([0, 0, 0])),
//             bar: null,
//         },
//         expiration: null,
//     });
// }

// await vault.save();

// console.log(cred?.data.password.expose());
