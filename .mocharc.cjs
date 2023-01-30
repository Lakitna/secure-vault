/**
 * @type {import("mocha").MochaOptions}
 */
const opts = {
    require: ['choma'],
    spec: ['./test/**/*.ts'],
    extensions: ['.ts'],
    recursive: true,
    'node-option': [
        'loader=ts-node/esm',
        'loader=esmock',
        'experimental-specifier-resolution=node',
    ],
    'watch-files': ['./test/**/*.ts', './src/**/*.ts'],
};

module.exports = opts;
