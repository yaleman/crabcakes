// Bundle AWS SDK for browser use
import { build } from 'esbuild';

await build({
    entryPoints: ['src/js/bucket-operations-src.js'],
    bundle: true,
    format: 'esm',
    platform: 'browser',
    outfile: 'static/js/bucket-operations.js',
    minify: true,
    sourcemap: false,
    external: [],
});
await build({
    entryPoints: ['src/js/troubleshooter.ts'],
    bundle: true,
    format: 'esm',
    platform: 'browser',
    outfile: 'static/js/troubleshooter.js',
    minify: true,
    sourcemap: false,
    external: [],
});

console.log('Javascript bundle created successfully');
