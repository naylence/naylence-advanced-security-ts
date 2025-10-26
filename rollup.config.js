import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import resolve from '@rollup/plugin-node-resolve';
import { existsSync } from 'node:fs';
import { resolve as resolvePath } from 'node:path';

const esmEntry = resolvePath('dist/esm/index.js');

if (!existsSync(esmEntry)) {
  throw new Error(
    'Browser build requires dist/esm/index.js. Run "npm run build:esm" before bundling or use "npm run build".'
  );
}

const externalPackages = new Set([
  '@naylence/core',
  '@naylence/factory',
  '@naylence/runtime',
  'naylence-runtime',
  'naylence-runtime-ts',
  'naylence-factory',
  'naylence-factory-ts',
  'naylence-core',
  'naylence-core-ts',
]);

const externalPrefixes = [
  '@naylence/core/',
  '@naylence/factory/',
  '@naylence/runtime/',
  'naylence-runtime/',
  'naylence-runtime-ts/',
];

export default {
  input: esmEntry,
  output: {
    file: 'dist/browser/index.js',
    format: 'es',
    sourcemap: true,
    inlineDynamicImports: true,
  },
  plugins: [
    resolve({
      browser: true,
      preferBuiltins: false,
    }),
    json(),
    commonjs(),
  ],
  external: (id) =>
    externalPackages.has(id) ||
    externalPrefixes.some((prefix) => id.startsWith(prefix)) ||
    id.startsWith('node:') ||
    id.startsWith('zod'),
};
