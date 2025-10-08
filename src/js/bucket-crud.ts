import { authenticatedFetch } from './csrf';

// Bucket CRUD operations

interface BucketResponse {
    bucket_name?: string;
    message?: string;
}

async function createBucket(bucketName: string): Promise<BucketResponse> {
    try {
        const response = await authenticatedFetch('/admin/api/buckets', {
            method: 'POST',
            body: JSON.stringify({ bucket_name: bucketName }),
            headers: {
                'Content-Type': 'application/json',
            },
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Failed to create bucket: ${error}`);
        }

        const result: BucketResponse = await response.json();
        return result;
    } catch (error) {
        console.error('Error creating bucket:', error);
        throw error;
    }
}

// Form handler for bucket creation page
function initBucketForm(): void {
    const form = document.getElementById('bucket-form') as HTMLFormElement | null;
    if (!form) return;

    form.addEventListener('submit', async (e: Event) => {
        e.preventDefault();

        const bucketNameInput = document.getElementById('bucket-name') as HTMLInputElement;
        const bucketName = bucketNameInput.value;

        try {
            await createBucket(bucketName);
            // Redirect to the new bucket
            const bucketNameEncoded = encodeURIComponent(bucketName);
            window.location.href = `/admin/buckets/${bucketNameEncoded}`;
        } catch (error) {
            // Show error in the form
            const message = error instanceof Error ? error.message : String(error);
            showError(message);
        }
    });
}

// Show error message in the form
function showError(message: string): void {
    const form = document.getElementById('bucket-form') || document.getElementById('bucket-delete-form');
    if (!form) return;

    // Remove any existing error messages
    const existingError = form.querySelector('.error-message');
    if (existingError) {
        existingError.remove();
    }

    // Create error message element
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.textContent = `Error: ${message}`;

    // Insert at the top of the form
    form.insertBefore(errorDiv, form.firstChild);
}

async function deleteBucket(bucketName: string, force: boolean = false): Promise<BucketResponse> {
    try {
        const bucketNameEncoded = encodeURIComponent(bucketName);
        const url = force
            ? `/admin/api/buckets/${bucketNameEncoded}?force=true`
            : `/admin/api/buckets/${bucketNameEncoded}`;

        const response = await authenticatedFetch(url, {
            method: 'DELETE',
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Failed to delete bucket: ${error}`);
        }

        const result: BucketResponse = await response.json();
        return result;
    } catch (error) {
        console.error('Error deleting bucket:', error);
        throw error;
    }
}

// Form handler for bucket deletion confirmation page
function initBucketDeleteForm(): void {
    const form = document.getElementById('bucket-delete-form') as HTMLFormElement | null;
    if (!form) return;

    const bucketNameInput = document.getElementById('bucket-name') as HTMLInputElement;
    const bucketName = bucketNameInput.value;
    const objectCountInput = document.getElementById('object-count') as HTMLInputElement;
    const objectCount = parseInt(objectCountInput.value, 10);
    const confirmNameInput = document.getElementById('confirm-bucket-name') as HTMLInputElement;
    const confirmCheckbox = document.getElementById('confirm-delete-objects') as HTMLInputElement | null;
    const deleteBtn = document.getElementById('delete-btn') as HTMLButtonElement;

    // Enable/disable delete button based on validation
    function validateForm(): void {
        const nameMatches = confirmNameInput.value === bucketName;
        const checkboxValid = objectCount === 0 || (confirmCheckbox && confirmCheckbox.checked);

        deleteBtn.disabled = !(nameMatches && checkboxValid);
    }

    confirmNameInput.addEventListener('input', validateForm);
    if (confirmCheckbox) {
        confirmCheckbox.addEventListener('change', validateForm);
    }

    form.addEventListener('submit', async (e: Event) => {
        e.preventDefault();

        try {
            const force = objectCount > 0;
            await deleteBucket(bucketName, force);
            // Redirect to buckets list
            window.location.href = '/admin/buckets';
        } catch (error) {
            // Show error in the form
            const message = error instanceof Error ? error.message : String(error);
            showError(message);
        }
    });
}

// Initialize on page load
function initBucketPages(): void {
    initBucketForm();
    initBucketDeleteForm();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initBucketPages);
} else {
    initBucketPages();
}
