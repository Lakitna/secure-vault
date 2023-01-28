import package_ from './package.json' assert { type: 'json' };
import typescript from '@rollup/plugin-typescript';
import externals from 'rollup-plugin-node-externals';
import copy from 'rollup-plugin-copy';
import cleanup from 'rollup-plugin-cleanup';
import dts from 'rollup-plugin-dts';

const outputDir = package_.files[0];

/**
 * @type {import('rollup').RollupOptions[]}
 */
export default [
    {
        input: ['src/index.ts'],
        output: [
            {
                file: package_.exports.import,
                format: 'module',
                sourcemap: true,
            },
            {
                file: package_.exports.require,
                format: 'commonjs',
            },
        ],
        plugins: [
            /**
             * Copy selected static files and assets to the output folder.
             */
            copy({
                targets: [
                    {
                        src: './src/prompt/popup-prompt.ps1',
                        dest: outputDir,
                    },
                ],
            }),

            /**
             * Support Typescript files
             */
            typescript(),

            /**
             * Remove comments, docstrings, and whitespace. We will ship docstrings as part of the
             * types instead.
             */
            cleanup({
                extensions: ['.ts', '.js'],
            }),

            /**
             * Mark all dependencies and node defaults as external to prevent
             * Rollup from including them in the bundle. We'll let the package
             * manager take care of dependency resolution and stuff so we don't
             * have to download the exact same code multiple times, once in
             * this bundle and also as a dependency of another package.
             */
            externals(),
        ],
    },
    {
        input: './src/index.ts',
        output: [
            {
                file: package_.types,
            },
        ],
        plugins: [
            /**
             * Generate bundled types (.d.ts)
             */
            dts(),

            /**
             * Mark all dependencies and node defaults as external to prevent
             * Rollup from including them in the bundle.
             */
            externals(),
        ],
    },
];
