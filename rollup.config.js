import typescript from '@rollup/plugin-typescript';
import externals from 'rollup-plugin-node-externals';
import copy from 'rollup-plugin-copy';

const outputDir = 'build';

/**
 * @type {import('rollup').RollupOptions[]}
 */
export default [
    {
        input: ['src/index.ts'],
        output: {
            dir: outputDir,
            format: 'es',
            sourcemap: true,
        },
        plugins: [
            /**
             * Copy select files to be used in the output as a static file.
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
             * Mark all dependencies and node defaults as external to prevent
             * Rollup from including them in the bundle. We'll let the package
             * manager take care of dependency resolution and stuff so we don't
             * have to download the exact same code multiple times, once in
             * this bundle and also as a dependency of another package.
             */
            externals(),
        ],
    },
];
