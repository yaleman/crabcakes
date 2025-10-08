// Credential CRUD operations
import { authenticatedFetch } from './csrf';


interface CredentialResponse {
    access_key_id?: string;
    message?: string;
}

async function deleteCredential(accessKeyId: string): Promise<void> {
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
        const message = error instanceof Error ? error.message : String(error);
        alert(`Error deleting credential: ${message}`);
    }
}

async function saveCredential(accessKeyId: string, secretAccessKey: string, isEdit: boolean): Promise<CredentialResponse> {
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

        const result: CredentialResponse = await response.json();
        return result;
    } catch (error) {
        console.error('Error saving credential:', error);
        throw error;
    }
}

// Generate a random 40-character secret key
function generateSecretKey(): string {
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
function initCredentialForm(): void {
    const form = document.getElementById('credential-form') as HTMLFormElement | null;
    if (!form) return;

    const accessKeyIdInput = document.getElementById('access-key-id') as HTMLInputElement;
    const secretKeyInput = document.getElementById('secret-access-key') as HTMLInputElement;
    const generateBtn = document.getElementById('generate-key-btn') as HTMLButtonElement | null;
    const toggleBtn = document.getElementById('toggle-visibility-btn') as HTMLButtonElement | null;

    // Handle generate button
    if (generateBtn) {
        generateBtn.addEventListener('click', (e: Event) => {
            e.preventDefault();
            const newKey = generateSecretKey();
            secretKeyInput.value = newKey;
            secretKeyInput.type = 'text'; // Show the generated key
        });
    }

    // Handle show/hide button
    if (toggleBtn) {
        toggleBtn.addEventListener('click', (e: Event) => {
            e.preventDefault();
            secretKeyInput.type = secretKeyInput.type === 'password' ? 'text' : 'password';
        });
    }

    // Handle form submission
    form.addEventListener('submit', async (e: Event) => {
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
            const newAccessKeyId = encodeURIComponent(accessKeyId);
            window.location.href = `/admin/identities/${newAccessKeyId}`
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            alert(`Error: ${message}`);
        }
    });
}

// Handler for credential detail page delete button
function initCredentialDetail(): void {
    const deleteBtn = document.getElementById('delete-credential-btn') as HTMLButtonElement | null;
    if (!deleteBtn) return;

    deleteBtn.addEventListener('click', (e: Event) => {
        e.preventDefault();
        const accessKeyId = deleteBtn.dataset.accessKeyId;
        if (accessKeyId) {
            deleteCredential(accessKeyId);
        }
    });
}

function initCredentialList(): void {
    const deleteButtons = document.querySelectorAll('.delete-temp-credential-btn');
    deleteButtons.forEach((btn) => {
        btn.addEventListener('click', (e: Event) => {
            e.preventDefault();
            if (!(e.target instanceof HTMLElement)) return;
            const accessKeyId = e.target.dataset.accesskeyid;
            console.debug(`Delete button clicked '${accessKeyId}'`);
            if (accessKeyId) {
                deleteTempCredential(accessKeyId);
            }
        });
    });
}

// Initialize on page load
function initCredentialPages(): void {
    initCredentialForm();
    initCredentialDetail();

    initCredentialList();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initCredentialPages);
} else {
    initCredentialPages();
}


async function deleteTempCredential(accessKeyId: string): Promise<void> {
    if (!confirm(`Are you sure you want to delete temporary credential ${accessKeyId}?`)) {
        return;
    }

    try {
        // Get CSRF token
        const csrfResponse = await fetch('/admin/api/csrf-token');
        const csrfData = await csrfResponse.json();

        // Delete the credential
        const response = await fetch(encodeURI(`/admin/api/temp_creds/${accessKeyId}`), {
            method: 'DELETE',
            headers: {
                'X-CSRF-Token': csrfData.csrf_token
            }
        });

        if (response.ok) {
            // Reload the page to show updated list
            window.location.reload();
        } else {
            const error = await response.json();
            alert(`Failed to delete credential: ${error.error || 'Unknown error'}`);
        }
    } catch (error) {
        alert(`Failed to delete credential: ${error instanceof Error ? error.message : String(error)}`);
    }
}