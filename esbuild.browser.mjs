import { build } from 'esbuild';
import path from 'path';

// Plugin to stub Node builtins that aren't needed in browser
const emptyNodeBuiltins = {
  name: 'empty-node-builtins',
  setup(build) {
    const builtins = ['crypto', 'stream', 'os', 'fs', 'http', 'https',
      'util', 'zlib', 'vm', 'assert', 'net', 'tls', 'child_process'];
    const filter = new RegExp(`^(${builtins.join('|')})$`);

    build.onResolve({ filter }, (args) => ({
      path: args.path,
      namespace: 'empty-node-builtin',
    }));

    build.onLoad({ filter: /.*/, namespace: 'empty-node-builtin' }, () => ({
      contents: 'export default {};',
      loader: 'js',
    }));
  },
};

const result = await build({
  entryPoints: ['src/browser.ts'],
  bundle: true,
  minify: true,
  sourcemap: true,
  format: 'iife',
  globalName: 'NostrNsecSeedphrase',
  outfile: 'dist/browser/nostr-nsec-seedphrase.min.js',
  target: ['es2020'],
  platform: 'browser',
  alias: {
    // Force CJS build of nostr-crypto-utils (its ESM output lacks .mjs extensions)
    'nostr-crypto-utils': path.resolve('node_modules/nostr-crypto-utils/dist/cjs/index.js'),
  },
  define: {
    'process.env.NODE_ENV': '"production"',
    'global': 'globalThis',
  },
  plugins: [emptyNodeBuiltins],
  metafile: true,
});

const output = Object.entries(result.metafile.outputs)
  .filter(([k]) => k.endsWith('.js'))
  .map(([k, v]) => `${k}: ${(v.bytes / 1024).toFixed(1)}KB`);
console.log('Browser bundle built:', output.join(', '));
