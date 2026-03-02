import path from 'path';
import webpack from 'webpack';
import { BundleAnalyzerPlugin } from 'webpack-bundle-analyzer';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default {
  entry: './src/browser.ts',
  mode: 'production',
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.js'],
    alias: {
      // Force webpack to use the CJS build of nostr-crypto-utils
      // (its ESM output lacks .mjs extensions and breaks without a loader)
      'nostr-crypto-utils': path.resolve(__dirname, 'node_modules/nostr-crypto-utils/dist/cjs/index.js'),
    },
    fallback: {
      crypto: false,
      stream: 'stream-browserify',
      buffer: 'buffer/',
      process: 'process/browser',
    },
  },
  output: {
    filename: 'nostr-nsec-seedphrase.min.js',
    path: path.resolve(__dirname, 'dist/browser'),
    library: {
      name: 'NostrNsecSeedphrase',
      type: 'umd',
      umdNamedDefine: true,
    },
    globalObject: 'this',
  },
  plugins: [
    new webpack.ProvidePlugin({
      Buffer: ['buffer', 'Buffer'],
      process: 'process/browser',
    }),
    new BundleAnalyzerPlugin({
      analyzerMode: 'static',
      openAnalyzer: false,
    }),
  ],
  optimization: {
    minimize: true,
  },
};
