#!/usr/bin/env node
/**
 * Create package.json files in dist/esm and dist/cjs to set module type
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const esmPackageJson = {
  type: 'module'
};

const cjsPackageJson = {
  type: 'commonjs'
};

try {
  mkdirSync(new URL('../dist/esm', import.meta.url).pathname, { recursive: true });
  mkdirSync(new URL('../dist/cjs', import.meta.url).pathname, { recursive: true });
  
  writeFileSync(
    new URL('../dist/esm/package.json', import.meta.url).pathname,
    JSON.stringify(esmPackageJson, null, 2) + '\n'
  );
  
  writeFileSync(
    new URL('../dist/cjs/package.json', import.meta.url).pathname,
    JSON.stringify(cjsPackageJson, null, 2) + '\n'
  );
  
  console.log('✓ Created module type package.json files in dist/esm and dist/cjs');
} catch (error) {
  console.error('Failed to create package.json files:', error);
  process.exit(1);
}
