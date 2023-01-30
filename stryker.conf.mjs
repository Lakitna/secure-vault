/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
const config = {
    packageManager: 'npm',
    reporters: ['html', 'progress'],
    checkers: ['typescript'],
    tsconfigFile: 'tsconfig.json',
    testRunnerNodeArgs: [
        '--loader=ts-node/esm',
        '--loader=esmock',
        '--experimental-specifier-resolution=node',
    ],
    testRunner: 'mocha',
    coverageAnalysis: 'perTest',
    ignoreStatic: true,

    // TODO: keep or nah?
    // timeoutMS: 50_000,
    timeoutFactor: 500,
};
export default config;
