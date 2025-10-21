// Bucket object operations using AWS SDK v3
import { S3Client, GetObjectCommand, DeleteObjectCommand, DeleteObjectsCommand } from '@aws-sdk/client-s3';
import { sessionCredentials, SessionData } from './shared';

interface S3Object {
    bucket: string;
    key: string;
}

interface DeleteError {
    Key?: string;
    Message?: string;
}

interface DeleteResponse {
    Deleted?: Array<{ Key?: string }>;
    Errors?: DeleteError[];
}

// Track selected objects
const selectedObjects = new Set<S3Object>();

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

// Download an object
async function downloadObject(bucket: string, key: string): Promise<void> {
    try {
        const client = await getS3Client().catch(() => { throw new Error('Failed to get S3 client'); });
        const command = new GetObjectCommand({
            Bucket: bucket,
            Key: key,
        });
        const response = await client.send(command);

        if (!response.Body) {
            throw new Error('No response body received');
        }

        // Convert response body to blob
        const blob = await response.Body.transformToByteArray();
        const blobObj = new Blob([blob as BlobPart]);

        // Create download link
        const url = URL.createObjectURL(blobObj);
        const a = document.createElement('a');
        a.href = url;
        a.download = key.split('/').pop() || key; // Use last part of key as filename
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Error downloading object:', error);
        const message = error instanceof Error ? error.message : String(error);
        alert(`Error downloading object: ${message}`);
    }
}

// Delete a single object
async function deleteObject(bucket: string, key: string): Promise<void> {
    if (!confirm(`Are you sure you want to delete "${key}"?`)) {
        return;
    }


    try {
        const client = await getS3Client().catch(() => { throw new Error('Failed to get S3 client'); });;
        const command = new DeleteObjectCommand({
            Bucket: bucket,
            Key: key,
        });

        await client.send(command);
        alert('Object deleted successfully');
        window.location.reload();
    } catch (error) {
        console.error('Error deleting object:', error);
        const message = error instanceof Error ? error.message : String(error);
        alert(`Error deleting object: ${message}`);
    }
}

// Toggle object selection
function toggleObjectSelection(checkbox: HTMLInputElement): void {
    const key = checkbox.dataset.key;
    const bucket = checkbox.dataset.bucket;

    if (!key || !bucket) {
        console.error('Checkbox missing required data attributes');
        return;
    }

    if (checkbox.checked) {
        selectedObjects.add({ bucket, key });
    } else {
        // Remove by finding matching object
        for (const obj of selectedObjects) {
            if (obj.bucket === bucket && obj.key === key) {
                selectedObjects.delete(obj);
                break;
            }
        }
    }

    updateBulkDeleteButton();
}

// Toggle select all
function toggleSelectAll(checkbox: HTMLInputElement): void {
    const checkboxes = document.querySelectorAll<HTMLInputElement>('.object-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = checkbox.checked;
        toggleObjectSelection(cb);
    });
}

// Update bulk delete button state
function updateBulkDeleteButton(): void {
    const bulkDeleteBtn = document.getElementById('bulk-delete-btn') as HTMLButtonElement | null;
    const counter = document.getElementById('selection-counter');
    const count = selectedObjects.size;

    if (bulkDeleteBtn) {
        bulkDeleteBtn.disabled = count === 0;
    }

    if (counter) {
        counter.textContent = `${count} item${count !== 1 ? 's' : ''} selected`;
    }
}

// Delete batch of selected objects
async function deleteBatchObjects(): Promise<void> {
    const count = selectedObjects.size;

    if (count === 0) {
        return;
    }

    if (!confirm(`Are you sure you want to delete ${count} object${count !== 1 ? 's' : ''}?`)) {
        return;
    }

    try {
        // Group objects by bucket (in case we have multiple buckets selected)
        const byBucket: Record<string, Array<{ Key: string }>> = {};
        for (const obj of selectedObjects) {
            if (!byBucket[obj.bucket]) {
                byBucket[obj.bucket] = [];
            }
            byBucket[obj.bucket].push({ Key: obj.key });
        }

        const client = await getS3Client();
        let totalDeleted = 0;
        let totalErrors = 0;

        // Delete objects for each bucket
        for (const [bucket, objects] of Object.entries(byBucket)) {
            const command = new DeleteObjectsCommand({
                Bucket: bucket,
                Delete: {
                    Objects: objects,
                    Quiet: false,
                },
            });

            const response = await client.send(command) as DeleteResponse;

            if (response.Deleted) {
                totalDeleted += response.Deleted.length;
            }

            if (response.Errors) {
                totalErrors += response.Errors.length;
                response.Errors.forEach(error => {
                    const ERROR_DELETE_FORMAT = 'Error deleting %s/%s: %s';
                    console.error(ERROR_DELETE_FORMAT, bucket, error.Key, error.Message);
                });
            }
        }

        if (totalErrors > 0) {
            alert(`Deleted ${totalDeleted} object(s). ${totalErrors} error(s) occurred.`);
        } else {
            alert(`Successfully deleted ${totalDeleted} object(s)`);
        }

        window.location.reload();
    } catch (error) {
        console.error('Error deleting objects:', error);
        const message = error instanceof Error ? error.message : String(error);
        alert(`Error deleting objects: ${message}`);
    }
}

// Initialize event handlers when the page loads
function initializeBucketOperations(): void {
    // Bind download button events
    document.querySelectorAll<HTMLButtonElement>('.download-object-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const bucket = btn.dataset.bucket;
            const key = btn.dataset.key;
            if (bucket && key) {
                downloadObject(bucket, key);
            }
        });
    });

    // Bind delete button events
    document.querySelectorAll<HTMLButtonElement>('.delete-object-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const bucket = btn.dataset.bucket;
            const key = btn.dataset.key;
            if (bucket && key) {
                deleteObject(bucket, key);
            }
        });
    });

    // Bind bulk delete button
    const bulkDeleteBtn = document.getElementById('bulk-delete-btn') as HTMLButtonElement | null;
    if (bulkDeleteBtn) {
        bulkDeleteBtn.addEventListener('click', (e) => {
            e.preventDefault();
            deleteBatchObjects();
        });
    }

    // Bind select all checkbox
    const selectAllCheckbox = document.getElementById('select-all') as HTMLInputElement | null;
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', (e) => {
            toggleSelectAll(e.target as HTMLInputElement);
        });
    }

    // Bind individual object checkboxes
    document.querySelectorAll<HTMLInputElement>('.object-checkbox').forEach(checkbox => {
        checkbox.addEventListener('change', (e) => {
            toggleObjectSelection(e.target as HTMLInputElement);
        });
    });
}

// Initialize when DOM is loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeBucketOperations);
} else {
    initializeBucketOperations();
}
