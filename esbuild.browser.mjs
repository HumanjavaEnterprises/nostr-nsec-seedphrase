/**
 * Builds the standalone <script> asset: dist/browser/nostr-nsec-seedphrase.min.js,
 * an IIFE that defines the global `NostrNsecSeedphrase`.
 *
 * This file is NOT the `browser` export condition. Bundlers (Vite, webpack,
 * esbuild) resolve the package to the ESM build (dist/index.js). The IIFE is
 * only for plain <script> tags (unpkg / jsdelivr).
 */
import { build } from 'esbuild';

const result = await build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  minify: true,
  format: 'iife',
  globalName: 'NostrNsecSeedphrase',
  outfile: 'dist/browser/nostr-nsec-seedphrase.min.js',
  target: ['es2020'],
  platform: 'browser',
  metafile: true,
});

const output = Object.entries(result.metafile.outputs)
  .filter(([k]) => k.endsWith('.js'))
  .map(([k, v]) => `${k}: ${(v.bytes / 1024).toFixed(1)}KB`);
console.log('Browser <script> bundle built:', output.join(', '));
