// @ts-check
/**
 * ESLint flat configuration.
 *
 * Type-aware linting is enabled for all first-party TypeScript (via
 * `tsconfig.eslint.json`) so that rules which depend on type information —
 * e.g. `no-floating-promises`, `no-misused-promises`, `no-unsafe-*` — can run.
 * These are exactly the rules that matter most for a token/crypto library,
 * where an unhandled promise or an `any` slipping through can be a security bug.
 */

import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import prettier from 'eslint-config-prettier';

export default tseslint.config(
  // Never lint build output, dependencies, coverage or the config files.
  {
    ignores: ['dist/**', 'node_modules/**', 'coverage/**', '*.config.js', '*.config.mjs', '*.cjs'],
  },

  // Base JS + type-checked TS rule sets.
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,

  // Project-wide language options and rule tuning.
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      parserOptions: {
        project: ['./tsconfig.eslint.json'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // Correctness — promote the highest-signal rules to errors.
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      '@typescript-eslint/await-thenable': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/switch-exhaustiveness-check': 'error',
      'no-console': 'error',
      eqeqeq: ['error', 'always'],
      'no-implicit-coercion': 'error',

      // Consistency — enforce `import type` so the emitted JS has no dead imports.
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { prefer: 'type-imports', fixStyle: 'inline-type-imports' },
      ],

      // Allow intentionally-unused args/vars when prefixed with `_`.
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },

  // Examples and tests are allowed to log and to be less strict about typing.
  {
    files: ['examples/**/*.ts', 'test/**/*.ts'],
    rules: {
      'no-console': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
    },
  },

  // Disable stylistic rules that Prettier owns — must be last.
  prettier,
);
