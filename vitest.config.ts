import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        globals: true,
        environment: 'happy-dom',
        setupFiles: ['./src/js/tests/setup.ts'],
        coverage: {
            provider: 'v8',
            reporter: ['text', 'json', 'html'],
            exclude: [
                'node_modules/',
                'src/js/tests/',
                '*.config.*',
                'build-js.js',
                'target/',
                'static/',
            ],
        },
    },
    resolve: {
        alias: {
            '@': '/src',
        },
    },
});
