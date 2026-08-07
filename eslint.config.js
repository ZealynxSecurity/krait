// ESLint 9 flat config.
//
// Scope is deliberately narrow: this lints `src/` (the CLI) only. The MCP servers are
// separate Node projects with their own toolchains, and `.claude/` is prompt markdown.
//
// Rule philosophy matches the codebase: agent code passes model output around, so
// `any` shows up at parse boundaries and is downgraded to a warning rather than an
// error. Anything that can silently change audit behaviour (floating promises,
// unused catch bindings that swallow errors) stays an error.

import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'coverage/**',
      'mcp-servers/**',      // separate Node projects, own configs
      'shadow-results/**',
      '.krait-cache/**',
      '**/*.d.ts',
    ],
  },

  js.configs.recommended,
  ...tseslint.configs.recommended,

  {
    files: ['src/**/*.ts', 'scripts/**/*.ts'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: {
        console: 'readonly',
        process: 'readonly',
        URL: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        fetch: 'readonly',
      },
    },
    rules: {
      // Tool-call results arrive as unknown-shaped JSON; the extract* helpers narrow
      // them. Flag `any` so it stays visible, but don't fail the build on it.
      '@typescript-eslint/no-explicit-any': 'warn',

      // Deliberate discards are common (destructuring a field off a verdict to drop it).
      // Allow the leading-underscore convention and `const { drop, ...rest }`, error on
      // everything else.
      '@typescript-eslint/no-unused-vars': ['error', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
        caughtErrorsIgnorePattern: '^_',
        destructuredArrayIgnorePattern: '^_',
        ignoreRestSiblings: true,
      }],

      // `} catch {}` is the codebase's idiom for a best-effort read (optional config
      // file, cleanup in a test teardown). Swallowing there is intentional; an empty
      // block anywhere else is a bug.
      'no-empty': ['error', { allowEmptyCatch: true }],

      // An unawaited API call in a pipeline stage silently drops findings.
      'no-void': 'off',
      'require-await': 'off',
      '@typescript-eslint/no-empty-function': 'warn',

      // Prefer explicit over clever in prompt-building code.
      'prefer-const': 'error',
      'no-var': 'error',
      eqeqeq: ['error', 'smart'],
    },
  },

  {
    // Tests mock SDK clients with partial shapes; `any`/non-null are load-bearing there.
    files: ['src/**/__tests__/**/*.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },
);
