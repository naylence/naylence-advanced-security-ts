import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const require = createRequire(import.meta.url);

const packageMappings = [
  {
    alias: '@naylence/core',
    localDir: '../naylence-core-ts/dist/cjs',
    packageEntry: '@naylence/core/dist/cjs/index.js',
  },
  {
    alias: '@naylence/factory',
    localDir: '../naylence-factory-ts/dist/cjs',
    packageEntry: '@naylence/factory/dist/cjs/index.js',
  },
  {
    alias: '@naylence/runtime',
    localDir: '../naylence-runtime-ts/dist/cjs',
    packageEntry: '@naylence/runtime/dist/cjs/index.js',
  },
  {
    alias: 'naylence-core',
    localDir: '../naylence-core-ts/dist/cjs',
    fallbackAlias: '@naylence/core',
  },
  {
    alias: 'naylence-core-ts',
    localDir: '../naylence-core-ts/dist/cjs',
    fallbackAlias: '@naylence/core',
  },
  {
    alias: 'naylence-factory',
    localDir: '../naylence-factory-ts/dist/cjs',
    fallbackAlias: '@naylence/factory',
  },
  {
    alias: 'naylence-factory-ts',
    localDir: '../naylence-factory-ts/dist/cjs',
    fallbackAlias: '@naylence/factory',
  },
  {
    alias: 'naylence-runtime',
    localDir: '../naylence-runtime-ts/dist/cjs',
    fallbackAlias: '@naylence/runtime',
  },
  {
    alias: 'naylence-runtime-ts',
    localDir: '../naylence-runtime-ts/dist/cjs',
    fallbackAlias: '@naylence/runtime',
  },
];

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const moduleNameMapper = {
  '^(\\.{1,2}/.*)\\.js$': '$1',
};

const resolutionCache = new Map();

for (const { alias, localDir, packageEntry, fallbackAlias } of packageMappings) {
  const aliasRegex = escapeRegex(alias);
  const distDir = resolve(__dirname, localDir);
  const indexPath = resolve(distDir, 'index.js');
  const hasLocalBuild = existsSync(indexPath);

  let resolvedIndexPath = hasLocalBuild ? indexPath : null;
  let resolvedDir = hasLocalBuild ? distDir : null;

  if (!hasLocalBuild && packageEntry) {
    try {
      resolvedIndexPath = require.resolve(packageEntry);
      resolvedDir = dirname(resolvedIndexPath);
    } catch (error) {
      // Fall back to package alias if resolution fails.
      resolvedIndexPath = null;
      resolvedDir = null;
    }
  }

  if (!resolvedIndexPath && fallbackAlias) {
    const fallbackResolution = resolutionCache.get(fallbackAlias);
    if (fallbackResolution) {
      resolvedIndexPath = fallbackResolution.indexPath;
      resolvedDir = fallbackResolution.dir;
    } else {
      moduleNameMapper[`^${aliasRegex}$`] = fallbackAlias;
      moduleNameMapper[`^${aliasRegex}/(.*)$`] = `${fallbackAlias}/$1`;
      continue;
    }
  }

  moduleNameMapper[`^${aliasRegex}$`] = resolvedIndexPath ?? alias;
  moduleNameMapper[`^${aliasRegex}/(.*)$`] = resolvedDir
    ? `${resolvedDir}/$1`
    : `${alias}/$1`;

  if (resolvedIndexPath && resolvedDir) {
    resolutionCache.set(alias, { indexPath: resolvedIndexPath, dir: resolvedDir });
  }
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
    'node_modules/(?!(@naylence|@noble|yaml|jose)/)',
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
