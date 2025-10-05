// Credential CRUD operations

async function deleteCredential(accessKeyId) {
    if (!confirm(`Are you sure you want to delete credential "${accessKeyId}"?`)) {
        return;
    }

    try {
        const response = await authenticatedFetch(`/admin/api/credentials/${accessKeyId}`, {
            method: 'DELETE',
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Failed to delete credential: ${error}`);
        }

        // Redirect to identities list
        window.location.href = '/admin/identities';
    } catch (error) {
        console.error('Error deleting credential:', error);
        alert(`Error deleting credential: ${error.message}`);
    }
}

async function saveCredential(accessKeyId, secretAccessKey, isEdit) {
    try {
        const url = isEdit
            ? `/admin/api/credentials/${accessKeyId}`
            : '/admin/api/credentials';
        const method = isEdit ? 'PUT' : 'POST';

        const body = isEdit
            ? { secret_access_key: secretAccessKey }
            : { access_key_id: accessKeyId, secret_access_key: secretAccessKey };

        const response = await authenticatedFetch(url, {
            method: method,
            body: body,
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Failed to save credential: ${error}`);
        }

        const result = await response.json();
        return result;
    } catch (error) {
        console.error('Error saving credential:', error);
        throw error;
    }
}

// Generate a random 40-character secret key
function generateSecretKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let result = '';
    const randomValues = new Uint8Array(40);
    crypto.getRandomValues(randomValues);

    for (let i = 0; i < 40; i++) {
        result += chars[randomValues[i] % chars.length];
    }

    return result;
}

// Form handler for credential edit page
function initCredentialForm() {
    const form = document.getElementById('credential-form');
    if (!form) return;

    const accessKeyIdInput = document.getElementById('access-key-id');
    const secretKeyInput = document.getElementById('secret-access-key');
    const generateBtn = document.getElementById('generate-key-btn');
    const toggleBtn = document.getElementById('toggle-visibility-btn');

    // Handle generate button
    if (generateBtn) {
        generateBtn.addEventListener('click', (e) => {
            e.preventDefault();
            const newKey = generateSecretKey();
            secretKeyInput.value = newKey;
            secretKeyInput.type = 'text'; // Show the generated key
        });
    }

    // Handle show/hide button
    if (toggleBtn) {
        toggleBtn.addEventListener('click', (e) => {
            e.preventDefault();
            secretKeyInput.type = secretKeyInput.type === 'password' ? 'text' : 'password';
        });
    }

    // Handle form submission
    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const accessKeyId = accessKeyIdInput.value.trim();
        const secretAccessKey = secretKeyInput.value;
        const isEdit = accessKeyIdInput.hasAttribute('readonly');

        // Validate secret key length
        if (secretAccessKey.length !== 40) {
            alert('Secret access key must be exactly 40 characters long');
            return;
        }

        try {
            await saveCredential(accessKeyId, secretAccessKey, isEdit);
            alert('Credential saved successfully!');
            window.location.href = `/admin/identities/${accessKeyId}`;
        } catch (error) {
            alert(`Error: ${error.message}`);
        }
    });
}

// Handler for credential detail page delete button
function initCredentialDetail() {
    const deleteBtn = document.getElementById('delete-credential-btn');
    if (!deleteBtn) return;

    deleteBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const accessKeyId = deleteBtn.dataset.accessKeyId;
        deleteCredential(accessKeyId);
    });
}

// Initialize on page load
function initCredentialPages() {
    initCredentialForm();
    initCredentialDetail();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initCredentialPages);
} else {
    initCredentialPages();
}
