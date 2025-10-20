// Bucket website configuration using AWS SDK v3
import {
    S3Client,
    HeadObjectCommand,
    GetBucketWebsiteCommand,
    PutBucketWebsiteCommand,
    DeleteBucketWebsiteCommand
} from '@aws-sdk/client-s3';
import { sessionCredentials, SessionData } from './shared';

// Get bucket name from URL
function getBucketName(): string {
    const pathParts = window.location.pathname.split('/');
    const bucketsIndex = pathParts.indexOf('buckets');
    if (bucketsIndex >= 0 && pathParts.length > bucketsIndex + 1) {
        return pathParts[bucketsIndex + 1];
    }
    throw new Error('Could not determine bucket name from URL');
}

// Get S3 client configured with credentials from localStorage
async function getS3Client(): Promise<S3Client> {
    const creds: SessionData | null = await sessionCredentials();

    if (!creds || creds === null) {
        throw new Error('No credentials found. Please refresh the page.');
    }
    return new S3Client({
        region: 'crabcakes',
        endpoint: window.location.origin,
        credentials: {
            accessKeyId: creds.access_key_id,
            secretAccessKey: creds.secret_access_key,
        },
        forcePathStyle: true,
    });
}

// Elements
const errorMessage = document.getElementById('error-notification') as HTMLDivElement;
const websiteEnabled = document.getElementById('website-enabled') as HTMLInputElement;
const indexSuffix = document.getElementById('index-suffix') as HTMLInputElement;
const errorKey = document.getElementById('error-key') as HTMLInputElement;
const indexStatus = document.getElementById('index-status') as HTMLSpanElement;
const errorStatus = document.getElementById('error-status') as HTMLSpanElement;
const deleteBtn = document.getElementById('delete-btn') as HTMLButtonElement;
const configFields = document.getElementById('website-config-fields') as HTMLDivElement;
const form = document.getElementById('website-config-form') as HTMLFormElement;

const bucketName = getBucketName();

// Show error message
function showError(message: string): void {
    errorMessage.textContent = message;
    errorMessage.classList.remove('error-notification-hide');
}

// Hide error message
function hideError(): void {
    errorMessage.textContent = '';
    errorMessage.classList.add('error-notification-hide');
}

// Load current configuration
async function loadConfiguration(): Promise<void> {
    try {
        const client = await getS3Client();
        const response = await client.send(new GetBucketWebsiteCommand({
            Bucket: bucketName
        }));

        // Config exists - populate form
        websiteEnabled.checked = true;
        configFields.classList.remove('hidden');
        deleteBtn.classList.remove('hidden');

        if (response.IndexDocument?.Suffix) {
            indexSuffix.value = response.IndexDocument.Suffix;
            await checkFileStatus(response.IndexDocument.Suffix, indexStatus);
        }

        if (response.ErrorDocument?.Key) {
            errorKey.value = response.ErrorDocument.Key;
            await checkFileStatus(response.ErrorDocument.Key, errorStatus);
        }
    } catch (error) {
        // No config - show empty form
        websiteEnabled.checked = false;
        configFields.classList.add('hidden');
        deleteBtn.classList.add('hidden');
    }
}

// Check if file exists
async function checkFileStatus(key: string, statusElement: HTMLSpanElement): Promise<void> {
    if (!key) {
        statusElement.textContent = '';
        return;
    }

    try {
        const client = await getS3Client();
        await client.send(new HeadObjectCommand({
            Bucket: bucketName,
            Key: key
        }));
        statusElement.textContent = '✓ exists';
        statusElement.className = 'file-status exists';
    } catch {
        statusElement.textContent = '⚠ not found';
        statusElement.className = 'file-status not-found';
    }
}

// Debounced file checking on input
let checkTimeout: number;

indexSuffix.addEventListener('input', () => {
    clearTimeout(checkTimeout);
    checkTimeout = window.setTimeout(() => checkFileStatus(indexSuffix.value, indexStatus), 500);
});

errorKey.addEventListener('input', () => {
    clearTimeout(checkTimeout);
    checkTimeout = window.setTimeout(() => checkFileStatus(errorKey.value, errorStatus), 500);
});

// Toggle config fields visibility
websiteEnabled.addEventListener('change', () => {
    if (websiteEnabled.checked) {
        configFields.classList.remove('hidden');
    } else {
        configFields.classList.add('hidden');
    }
});

// Save configuration
form.addEventListener('submit', async (e) => {
    e.preventDefault();

    hideError();

    try {
        const client = await getS3Client();

        if (!websiteEnabled.checked) {
            // Delete configuration
            await client.send(new DeleteBucketWebsiteCommand({
                Bucket: bucketName
            }));
        } else {
            // Save configuration
            const config: any = {
                IndexDocument: { Suffix: indexSuffix.value || 'index.html' }
            };

            if (errorKey.value) {
                config.ErrorDocument = { Key: errorKey.value };
            }

            await client.send(new PutBucketWebsiteCommand({
                Bucket: bucketName,
                WebsiteConfiguration: config
            }));
        }

        // Success - redirect to bucket detail
        window.location.href = `/admin/buckets/${bucketName}`;
    } catch (error) {
        // Show error message at top
        const errorMsg = error instanceof Error ? error.message : String(error);
        showError(`Failed to save configuration: ${errorMsg}`);
    }
});

// Delete configuration
deleteBtn.addEventListener('click', async () => {
    hideError();

    try {
        const client = await getS3Client();
        await client.send(new DeleteBucketWebsiteCommand({
            Bucket: bucketName
        }));

        // Success - redirect to bucket detail
        window.location.href = `/admin/buckets/${bucketName}`;
    } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        showError(`Failed to delete configuration: ${errorMsg}`);
    }
});

// Load config on page load
loadConfiguration();
