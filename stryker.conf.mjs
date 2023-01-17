/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
const config = {
    packageManager: 'npm',
    reporters: ['html', 'progress'],
    checkers: ['typescript'],
    tsconfigFile: 'tsconfig.json',
    testRunnerNodeArgs: ['--loader=ts-node/esm', '--experimental-specifier-resolution=node'],
    testRunner: 'mocha',
    coverageAnalysis: 'perTest',
    ignoreStatic: true,

    // TODO: keep or nah?
    timeoutMS: 100_000,
};
export default config;
