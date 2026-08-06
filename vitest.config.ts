import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],

    // Coverage configuration
    coverage: {
      provider: 'v8',
      reporter: ['text', 'text-summary', 'html', 'lcov', 'json'],
      reportsDirectory: './coverage',

      // Thresholds - adjust as needed
      thresholds: {
        statements: 70,
        branches: 60,
        functions: 70,
        lines: 70,
      },

      // Include source files in coverage
      include: [
        'src/lib/**/*.ts',
        'src/lib/craft/**/*.ts',
      ],

      // Exclude non-source files
      exclude: [
        'src/**/*.d.ts',
        'src/**/*.test.ts',
        'src/**/index.ts', // Re-export files
        'node_modules/**',
        'tests/**',
      ],
    },

    // Test timeout (can be overridden per-test)
    testTimeout: 10000, // 10s default
    hookTimeout: 10000,

    // Retry flaky tests (useful for CI)
    retry: 2,

    // Isolate tests for consistent behavior
    isolate: true,

    // Show progress for large test suites
    reportVerbose: true,

    // Setup files (if needed in future)
    // setupFiles: ['./tests/setup.ts'],
  },

  // Resolve aliases (if needed)
  resolve: {
    alias: {
      '@': '/src',
    },
  },
});
