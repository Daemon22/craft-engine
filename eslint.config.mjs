import { defineConfig } from 'eslint/config';
import nextVitals from 'eslint-config-next/core-web-vitals';
import nextTs from 'eslint-config-next/typescript';

export default defineConfig([
  nextVitals,
  nextTs,
  {
    ignores: [
      'node_modules/**',
      '.next/**',
      'dist/**',
      'coverage/**',
      'reports/**',
      'craft-codec/**',
      'bin/**',
      'public/**',
      'scripts/**',
      'tests/**',
    ],
  },
]);
