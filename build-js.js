// Bundle AWS SDK for browser use
import { build } from 'esbuild';
import { readdirSync } from 'fs';
import { join } from 'path';
// import { ESLint } from 'eslint';

const sourceDir = 'target/js/js/';
const outDir = 'static/js/';

async function buildfile(filepath) {
    console.log(`Building ${filepath}... to ${filepath.replace(sourceDir, outDir)}`);
    try {
        await build({
            entryPoints: [filepath],
            bundle: true,
            format: 'esm',
            platform: 'browser',
            // Output .js files regardless of input extension
            outfile: filepath.replace(sourceDir, outDir),
            minify: true,
            sourcemap: false,
            external: [],
        });
    } catch (err) {
        console.error(err);
        throw new Error('Build process failed');
    }
}

const files = readdirSync(sourceDir);
for (const file of files) {
    const filepath = join(sourceDir, file);
    // Process both .js and .ts files
    if (!file.endsWith('.js')) continue;

    buildfile(filepath);
}




console.log('Javascript bundle created successfully');
