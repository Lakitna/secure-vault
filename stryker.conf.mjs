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
    // Increase because we also run component tests with Stryker.
    timeoutFactor: 250,
};
export default config;
