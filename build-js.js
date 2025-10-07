// Bundle AWS SDK for browser use
import { build } from 'esbuild';
import { readdirSync } from 'fs';
import { join } from 'path';
// import { ESLint } from 'eslint';


async function buildfile(filepath) {
    console.log(`Building ${filepath}...`);
    try {
        await build({
            entryPoints: [filepath],
            bundle: true,
            format: 'esm',
            platform: 'browser',
            // Output .js files regardless of input extension
            outfile: filepath.replace("src/js", "static/js").replace('.ts', '.js'),
            minify: true,
            sourcemap: false,
            external: [],
        });
    } catch (err) {
        console.error(err);
        throw new Error('Build process failed');
    }
}

const files = readdirSync('./src/js/');
for (const file of files) {
    const filepath = join('./src/js/', file);
    // Process both .js and .ts files
    if (!file.endsWith('.js')) continue;

    buildfile(filepath);
}



// await build({
//     entryPoints: ['src/js/troubleshooter.ts'],
//     bundle: true,
//     format: 'esm',
//     platform: 'browser',
//     outfile: 'static/js/troubleshooter.js',
//     minify: true,
//     sourcemap: false,
//     external: [],
// });

console.log('Javascript bundle created successfully');
