// Bundle AWS SDK for browser use
import { build } from 'esbuild';
import { readdirSync } from 'fs';
import { join } from 'path';
import { ESLint } from 'eslint';

const files = readdirSync('./src/js/');
for (const file of files) {
    const filepath = join('./src/js/', file);
    if (!file.endsWith('.js')) continue;
    console.log(`Building ${filepath}...`);

    if (filepath.endsWith('.js')) {
        const eslint = new ESLint();
        const results = await eslint.lintFiles([filepath]);
        const formatter = await eslint.loadFormatter('stylish');
        const resultText = formatter.format(results);

        if (results.some(result => result.errorCount > 0)) {
            console.error(resultText);
            throw new Error(`ESLint found errors in ${filepath}`);
        }
        console.log(resultText);
    }


    try {
        await build({
            entryPoints: [filepath],
            bundle: true,
            format: 'esm',
            platform: 'browser',
            outfile: filepath.replace("src/js", "static/js"),
            minify: true,
            sourcemap: false,
            external: [],
        });
    } catch (err) {
        console.error(err);
        throw new Error('Build process failed');
    }
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
