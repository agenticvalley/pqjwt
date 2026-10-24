import { defineConfig } from 'vitest/config';

/**
 * Vitest configuration.
 *
 * Tests import the library through its source `.js` specifiers (the NodeNext
 * convention), which Vite resolves to the sibling `.ts` files. Coverage is
 * collected from `src/` with the pure re-export barrels and type-only modules
 * excluded, since they contain no executable logic.
 */
export default defineConfig({
  test: {
    environment: 'node',
    globals: false,
    include: ['test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      reportsDirectory: 'coverage',
      include: ['src/**/*.ts'],
      exclude: ['src/**/index.ts', 'src/**/types.ts'],
      thresholds: {
        lines: 80,
        functions: 80,
        statements: 80,
        branches: 70,
      },
    },
  },
});
