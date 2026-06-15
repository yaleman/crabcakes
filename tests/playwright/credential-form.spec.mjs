import { readFile } from 'node:fs/promises';

import { expect, test } from '@playwright/test';

const appOrigin = 'http://crabcakes.test';
const credentialScript = await readFile(
    new URL('../../static/js/credential-crud.js', import.meta.url),
    'utf8',
);
const credentialTemplate = await readFile(
    new URL('../../templates/credential_form.html', import.meta.url),
    'utf8',
);

function credentialFormHtml({ edit = false } = {}) {
    return `<!doctype html>
<html lang="en">
<body>
    <form id="credential-form">
        <input
            type="text"
            id="access-key-id"
            name="access-key-id"
            value="test-user"
            ${edit ? 'readonly' : ''}
            required
        >
        <input
            type="password"
            id="secret-access-key"
            name="secret-access-key"
            minlength="40"
            pattern=".{40}"
            required
        >
        <button type="button" id="generate-key-btn">Generate Random Key</button>
        <button type="button" id="toggle-visibility-btn">Show/Hide</button>
        <button type="submit">Save Credential</button>
    </form>
    <button type="button" id="delete-credential-btn" data-access-key-id="test-user">Delete</button>
    <script>${credentialScript}</script>
</body>
</html>`;
}

async function openCredentialForm(page, { edit = false } = {}) {
    const credentialRequests = [];

    await page.route(`${appOrigin}/admin/api/csrf-token`, async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ csrf_token: 'csrf-token' }),
        });
    });

    await page.route(/^http:\/\/crabcakes\.test\/admin\/api\/credentials(?:\/[^/]+)?$/, async (route) => {
        const request = route.request();
        credentialRequests.push({
            method: request.method(),
            url: request.url(),
            headers: request.headers(),
            body: JSON.parse(request.postData() ?? '{}'),
        });

        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ success: true, access_key_id: 'test-user' }),
        });
    });

    await page.route(`${appOrigin}/admin/identities/test-user`, async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'text/html',
            body: '<!doctype html><title>Identity</title>',
        });
    });

    await page.route(`${appOrigin}/admin/identities/new`, async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'text/html',
            body: credentialFormHtml({ edit }),
        });
    });

    await page.goto(`${appOrigin}/admin/identities/new`);
    return credentialRequests;
}

function collectDialogs(page) {
    const messages = [];
    page.on('dialog', async (dialog) => {
        messages.push(dialog.message());
        await dialog.accept();
    });
    return messages;
}

test('credential form rejects short secret keys with native validation before saving', async ({ page }) => {
    const credentialRequests = await openCredentialForm(page);

    await page.locator('#access-key-id').fill('short-secret-user');
    await page.locator('#secret-access-key').fill('too-short');
    await page.getByRole('button', { name: 'Save Credential' }).click();

    await expect(page.locator('#secret-access-key')).toBeFocused();
    await expect(page.locator('#secret-access-key')).toHaveJSProperty('validity.valid', false);
    expect(credentialRequests).toEqual([]);
});

test('credential template keeps native validation without silent truncation', () => {
    expect(credentialTemplate).toContain('<form id="credential-form">');
    expect(credentialTemplate).toContain('minlength="40"');
    expect(credentialTemplate).toContain('pattern=".{40}"');
    expect(credentialTemplate).not.toContain('maxlength="40"');
    expect(credentialTemplate).not.toContain('novalidate');
});

test('credential form rejects long secret keys with native validation instead of truncating them', async ({ page }) => {
    const credentialRequests = await openCredentialForm(page);
    const longSecret = 'A'.repeat(41);

    await page.locator('#access-key-id').fill('long-secret-user');
    await page.locator('#secret-access-key').fill(longSecret);

    await expect(page.locator('#secret-access-key')).toHaveValue(longSecret);

    await page.getByRole('button', { name: 'Save Credential' }).click();

    await expect(page.locator('#secret-access-key')).toBeFocused();
    await expect(page.locator('#secret-access-key')).toHaveJSProperty('validity.valid', false);
    expect(credentialRequests).toEqual([]);
});

test('credential form JavaScript rejects invalid secret length if native validation is bypassed', async ({ page }) => {
    const dialogs = collectDialogs(page);
    const credentialRequests = await openCredentialForm(page);

    await page.locator('#access-key-id').fill('js-fallback-user');
    await page.locator('#secret-access-key').fill('too-short');
    await page.$eval('#credential-form', (form) => {
        form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    });

    await expect.poll(() => dialogs).toContain('Secret access key must be exactly 40 characters long');
    expect(credentialRequests).toEqual([]);
});

test('credential form saves exactly 40 character secret keys unchanged', async ({ page }) => {
    const dialogs = collectDialogs(page);
    const credentialRequests = await openCredentialForm(page);
    const validSecret = 'A'.repeat(40);

    await page.locator('#access-key-id').fill('valid-secret-user');
    await page.locator('#secret-access-key').fill(validSecret);
    await page.getByRole('button', { name: 'Save Credential' }).click();

    await expect.poll(() => dialogs).toContain('Credential saved successfully!');
    expect(credentialRequests).toHaveLength(1);
    expect(credentialRequests[0]).toMatchObject({
        method: 'POST',
        body: {
            access_key_id: 'valid-secret-user',
            secret_access_key: validSecret,
        },
    });
    expect(credentialRequests[0].headers['x-csrf-token']).toBe('csrf-token');
});

test('credential edit form updates exactly 40 character secret keys unchanged', async ({ page }) => {
    const dialogs = collectDialogs(page);
    const credentialRequests = await openCredentialForm(page, { edit: true });
    const validSecret = 'B'.repeat(40);

    await page.locator('#secret-access-key').fill(validSecret);
    await page.getByRole('button', { name: 'Save Credential' }).click();

    await expect.poll(() => dialogs).toContain('Credential saved successfully!');
    expect(credentialRequests).toHaveLength(1);
    expect(credentialRequests[0]).toMatchObject({
        method: 'PUT',
        url: `${appOrigin}/admin/api/credentials/test-user`,
        body: {
            secret_access_key: validSecret,
        },
    });
});
