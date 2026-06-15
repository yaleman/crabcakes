import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
    testDir: './tests/playwright',
    outputDir: './target/playwright-results',
    reporter: 'list',
    use: {
        ...devices['Desktop Chrome'],
        trace: 'on-first-retry',
    },
});
