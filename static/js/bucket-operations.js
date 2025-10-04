// Bucket object operations using AWS SDK v3
import { S3Client, GetObjectCommand, DeleteObjectCommand, DeleteObjectsCommand } from 'https://cdn.jsdelivr.net/npm/@aws-sdk/client-s3@3/+esm';

// Track selected objects
const selectedObjects = new Set();

// Get S3 client configured with credentials from localStorage
function getS3Client() {
    const accessKeyId = localStorage.getItem('crabcakes_access_key_id');
    const secretAccessKey = localStorage.getItem('crabcakes_secret_access_key');

    if (!accessKeyId || !secretAccessKey) {
        throw new Error('No credentials found. Please refresh the page.');
    }

    return new S3Client({
        region: 'crabcakes',
        endpoint: window.location.origin,
        credentials: {
            accessKeyId,
            secretAccessKey,
        },
        forcePathStyle: true,
    });
}

// Download an object
async function downloadObject(bucket, key) {
    try {
        const client = getS3Client();
        const command = new GetObjectCommand({
            Bucket: bucket,
            Key: key,
        });

        const response = await client.send(command);

        // Convert response body to blob
        const blob = await response.Body.transformToByteArray();
        const blobObj = new Blob([blob]);

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
        alert(`Error downloading object: ${error.message}`);
    }
}

// Delete a single object
async function deleteObject(bucket, key) {
    if (!confirm(`Are you sure you want to delete "${key}"?`)) {
        return;
    }

    try {
        const client = getS3Client();
        const command = new DeleteObjectCommand({
            Bucket: bucket,
            Key: key,
        });

        await client.send(command);
        alert('Object deleted successfully');
        window.location.reload();
    } catch (error) {
        console.error('Error deleting object:', error);
        alert(`Error deleting object: ${error.message}`);
    }
}

// Toggle object selection
function toggleObjectSelection(checkbox) {
    const key = checkbox.dataset.key;
    const bucket = checkbox.dataset.bucket;

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
function toggleSelectAll(checkbox) {
    const checkboxes = document.querySelectorAll('.object-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = checkbox.checked;
        toggleObjectSelection(cb);
    });
}

// Update bulk delete button state
function updateBulkDeleteButton() {
    const bulkDeleteBtn = document.getElementById('bulk-delete-btn');
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
async function deleteBatchObjects() {
    const count = selectedObjects.size;

    if (count === 0) {
        return;
    }

    if (!confirm(`Are you sure you want to delete ${count} object${count !== 1 ? 's' : ''}?`)) {
        return;
    }

    try {
        // Group objects by bucket (in case we have multiple buckets selected)
        const byBucket = {};
        for (const obj of selectedObjects) {
            if (!byBucket[obj.bucket]) {
                byBucket[obj.bucket] = [];
            }
            byBucket[obj.bucket].push({ Key: obj.key });
        }

        const client = getS3Client();
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

            const response = await client.send(command);

            if (response.Deleted) {
                totalDeleted += response.Deleted.length;
            }

            if (response.Errors) {
                totalErrors += response.Errors.length;
                response.Errors.forEach(error => {
                    console.error(`Error deleting ${error.Key}:`, error.Message);
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
        alert(`Error deleting objects: ${error.message}`);
    }
}

// Make functions available globally
window.downloadObject = downloadObject;
window.deleteObject = deleteObject;
window.toggleObjectSelection = toggleObjectSelection;
window.toggleSelectAll = toggleSelectAll;
window.deleteBatchObjects = deleteBatchObjects;
