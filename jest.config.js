import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const packageMappings = [
  ['@naylence/core', '../naylence-core-ts/dist/cjs'],
  ['@naylence/factory', '../naylence-factory-ts/dist/cjs'],
  ['@naylence/runtime', '../naylence-runtime-ts/dist/cjs'],
  ['naylence-core', '../naylence-core-ts/dist/cjs'],
  ['naylence-core-ts', '../naylence-core-ts/dist/cjs'],
  ['naylence-factory', '../naylence-factory-ts/dist/cjs'],
  ['naylence-factory-ts', '../naylence-factory-ts/dist/cjs'],
  ['naylence-runtime', '../naylence-runtime-ts/dist/cjs'],
  ['naylence-runtime-ts', '../naylence-runtime-ts/dist/cjs'],
];

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const moduleNameMapper = {
  '^(\\.{1,2}/.*)\\.js$': '$1',
};

for (const [alias, relativeDir] of packageMappings) {
  const aliasRegex = escapeRegex(alias);
  const distDir = resolve(__dirname, relativeDir);
  const indexPath = resolve(distDir, 'index.js');
  const hasLocalBuild = existsSync(indexPath);

  moduleNameMapper[`^${aliasRegex}$`] = hasLocalBuild ? indexPath : alias;
  moduleNameMapper[`^${aliasRegex}/(.*)$`] = hasLocalBuild ? `${distDir}/$1` : `${alias}/$1`;
}

/** @type {import('ts-jest').JestConfigWithTsJest} */
export default {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  roots: [
    '<rootDir>/src',
  ],
  moduleNameMapper,
  transformIgnorePatterns: [
    'node_modules/(?!(@noble|yaml|jose)/)',
  ],
  transform: {
    '^.+\\.(ts|js|mjs)$': [
      'ts-jest',
      {
        useESM: true,
        tsconfig: {
          module: 'ESNext',
          moduleResolution: 'node',
          esModuleInterop: true,
          allowSyntheticDefaultImports: true,
          isolatedModules: true,
          sourceMap: true,
          inlineSources: true,
          inlineSourceMap: false, // Use separate source maps for better debugging
        },
        diagnostics: {
          ignoreCodes: [151001],
        },
      },
    ],
  },
  testMatch: [
    '**/__tests__/**/*.test.ts',
    '**/*.test.ts',
  ],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.test.ts',
    '!src/**/__tests__/**',
    '!src/**/index.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  maxWorkers: 1, // Sequential execution to prevent race conditions
  testTimeout: 30000, // Increased for integration tests
  setupFilesAfterEnv: [
    '<rootDir>/test/setup-crypto.ts',
    '<rootDir>/test/setup-factories.ts',
  ],
};
