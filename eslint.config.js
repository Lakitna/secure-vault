import globals from "globals";
import pluginJs from "@eslint/js";
import tseslint from "typescript-eslint";
import vitest from "eslint-plugin-vitest";

/** @type {import('eslint').Linter.Config} */
export default [
    {
        files: ["**/*.{js,mjs,cjs,ts}"],
    },
    {
        ignores: [
            '.stryker-tmp',
            'dist',
        ]
    },
    {
        languageOptions: {
            globals: globals.node,
        },
    },
    pluginJs.configs.recommended,
    ...tseslint.configs.recommended,
    {
        files: ['test/**/*'],
        plugins: {
            vitest,
        },
        rules: {
            ...vitest.configs.recommended.rules,
        },
        settings: {
            vitest: {
                typecheck: true
            }
        },
        languageOptions: {
            globals: {
                ...vitest.environments.env.globals,
            },
        },
    },
];
