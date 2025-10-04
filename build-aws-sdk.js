// Bundle AWS SDK for browser use
import { build } from 'esbuild';

await build({
    entryPoints: ['static/js/bucket-operations-src.js'],
    bundle: true,
    format: 'esm',
    platform: 'browser',
    outfile: 'static/js/bucket-operations.js',
    minify: true,
    sourcemap: false,
    external: [],
});

console.log('AWS SDK bundle created successfully');
