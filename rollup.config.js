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
    id === 'naylence-factory' || 
    id === 'naylence-factory-ts' || 
    id === 'naylence-runtime' ||
    id === 'naylence-runtime-ts' ||
    id === 'naylence-core' ||
    id === 'naylence-core-ts' ||
    id.startsWith('node:') ||
    id.startsWith('zod'),
};
