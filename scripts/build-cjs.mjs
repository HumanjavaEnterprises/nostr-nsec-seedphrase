/**
 * Emits the CommonJS build into dist/cjs/:
 *  - dist/cjs/index.js     (src/index.ts transpiled to CJS; dependencies stay external)
 *  - dist/cjs/index.d.ts   (copy of the ESM declarations, typed as CJS by the folder's package.json)
 *  - dist/cjs/package.json ({ "type": "commonjs" }) so Node loads dist/cjs/*.js as CJS
 *    even though the root package.json declares "type": "module".
 *
 * The runtime dependencies (@noble/*, @scure/*) are ESM-only, so require() of this
 * build relies on Node's require(esm) support (Node >= 20.19 / >= 22.12).
 */
import { build } from 'esbuild';
import { copyFileSync, mkdirSync, writeFileSync } from 'node:fs';

mkdirSync('dist/cjs', { recursive: true });
await build({
  entryPoints: ['src/index.ts'],
  outfile: 'dist/cjs/index.js',
  format: 'cjs',
  platform: 'neutral',
  target: ['es2020'],
  bundle: true,
  packages: 'external',
  logLevel: 'warning',
});
copyFileSync('dist/index.d.ts', 'dist/cjs/index.d.ts');
writeFileSync('dist/cjs/package.json', JSON.stringify({ type: 'commonjs' }, null, 2) + '\n');
console.log('Built dist/cjs (index.js, index.d.ts, package.json { "type": "commonjs" })');
