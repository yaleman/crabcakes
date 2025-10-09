// Policy CRUD operations
import { authenticatedFetch } from './csrf';
import { ErrorMessage } from './shared';

interface PolicyResponse {
    name?: string;
    message?: string;
}

async function deletePolicy(policyName: string): Promise<void> {
    if (!confirm(`Are you sure you want to delete policy "${policyName}"?`)) {
        return;
    }

    try {
        const response = await authenticatedFetch(`/admin/api/policies/${policyName}`, {
            method: 'DELETE',
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Failed to delete policy: ${error}`);
        }

        // Redirect to policies list
        window.location.href = '/admin/policies';
    } catch (error) {
        console.error('Error deleting policy:', error);
        const message = error instanceof Error ? error.message : String(error);
        alert(`Error deleting policy: ${message}`);
    }
}


async function savePolicy(policyName: string, policyData: any): Promise<PolicyResponse> {
    try {
        const isUpdate = policyName && policyName !== '';
        const url = isUpdate ? `/admin/api/policies/${policyName}` : '/admin/api/policies';
        const method = isUpdate ? 'PUT' : 'POST';

        const body = isUpdate ? policyData : { name: policyName, policy: policyData };

        const response = await authenticatedFetch(url, {
            method: method,
            body: body,
        });

        if (!response.ok) {
            const error = await response.json() as ErrorMessage;
            throw new Error(`Failed to save policy: ${error.error}`);
        }

        const result: PolicyResponse = await response.json();
        return result;
    } catch (error) {
        console.error('Error saving policy:', error);
        throw error;
    }
}

// Form handler for policy edit page
function initPolicyForm(): void {
    const form = document.getElementById('policy-form') as HTMLFormElement | null;
    if (!form) return;

    form.addEventListener('submit', async (e: Event) => {
        e.preventDefault();

        const policyNameInput = document.getElementById('policy-name') as HTMLInputElement;
        const policyJsonInput = document.getElementById('policy-json') as HTMLTextAreaElement;
        // strip all non-url-safe characters from policy name for redirect
        const policyName = encodeURIComponent(policyNameInput.value);
        const policyJson = policyJsonInput.value;

        try {
            const policyData = JSON.parse(policyJson);
            await savePolicy(policyName, policyData);
            window.location.href = `/admin/policies/${policyName}`;
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);

            const errorNotification = document.getElementById('error-notification') as HTMLDivElement | null;

            if (errorNotification) {
                errorNotification.textContent = message;
                while (errorNotification.classList.contains('error-notification-hide')) {
                    errorNotification.classList.remove('error-notification-hide');
                }
                errorNotification.classList.remove('error-notification-empty');
            } else {
                console.error("Error notification element not found");
            }
        }
    });
}

// Handler for policy detail page delete button
function initPolicyDetail(): void {
    const deleteBtn = document.getElementById('delete-policy-btn') as HTMLButtonElement | null;
    if (!deleteBtn) return;

    deleteBtn.addEventListener('click', (e: Event) => {
        e.preventDefault();
        const policyName = deleteBtn.dataset.policyName;
        if (policyName) {
            deletePolicy(policyName);
        }
    });
}

// Initialize on page load
function initPolicyPages(): void {
    const errors = document.getElementsByClassName('error-notification');
    Array.from(errors).forEach((errorNotification) => {
        console.debug(errorNotification.textContent.trim().length);
        if (errorNotification.textContent.trim().length == 0) {
            console.debug("empty");
            errorNotification.classList.add('error-notification-hide');
        } else {
            errorNotification.classList.remove('error-notification-hide');
        }
    });
    initPolicyForm();
    initPolicyDetail();
    console.debug("Finished startup");
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initPolicyPages);
} else {
    initPolicyPages();
}
