// Bucket CRUD operations

async function createBucket(bucketName) {
    try {
        const response = await authenticatedFetch('/admin/api/buckets', {
            method: 'POST',
            body: { bucket_name: bucketName },
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Failed to create bucket: ${error}`);
        }

        const result = await response.json();
        return result;
    } catch (error) {
        console.error('Error creating bucket:', error);
        throw error;
    }
}

// Form handler for bucket creation page
function initBucketForm() {
    const form = document.getElementById('bucket-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const bucketName = document.getElementById('bucket-name').value;

        try {
            await createBucket(bucketName);
            // Redirect to the new bucket
            window.location.href = `/admin/buckets/${bucketName}`;
        } catch (error) {
            // Show error in the form
            showError(error.message);
        }
    });
}

// Show error message in the form
function showError(message) {
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

async function deleteBucket(bucketName, force = false) {
    try {
        const url = force
            ? `/admin/api/buckets/${bucketName}?force=true`
            : `/admin/api/buckets/${bucketName}`;

        const response = await authenticatedFetch(url, {
            method: 'DELETE',
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Failed to delete bucket: ${error}`);
        }

        const result = await response.json();
        return result;
    } catch (error) {
        console.error('Error deleting bucket:', error);
        throw error;
    }
}

// Form handler for bucket deletion confirmation page
function initBucketDeleteForm() {
    const form = document.getElementById('bucket-delete-form');
    if (!form) return;

    const bucketName = document.getElementById('bucket-name').value;
    const objectCount = parseInt(document.getElementById('object-count').value, 10);
    const confirmNameInput = document.getElementById('confirm-bucket-name');
    const confirmCheckbox = document.getElementById('confirm-delete-objects');
    const deleteBtn = document.getElementById('delete-btn');

    // Enable/disable delete button based on validation
    function validateForm() {
        const nameMatches = confirmNameInput.value === bucketName;
        const checkboxValid = objectCount === 0 || (confirmCheckbox && confirmCheckbox.checked);

        deleteBtn.disabled = !(nameMatches && checkboxValid);
    }

    confirmNameInput.addEventListener('input', validateForm);
    if (confirmCheckbox) {
        confirmCheckbox.addEventListener('change', validateForm);
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        try {
            const force = objectCount > 0;
            await deleteBucket(bucketName, force);
            // Redirect to buckets list
            window.location.href = '/admin/buckets';
        } catch (error) {
            // Show error in the form
            showError(error.message);
        }
    });
}

// Initialize on page load
function initBucketPages() {
    initBucketForm();
    initBucketDeleteForm();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initBucketPages);
} else {
    initBucketPages();
}
