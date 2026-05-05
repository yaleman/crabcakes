// Policy CRUD operations
import { authenticatedFetch } from './csrf';
import { ErrorMessage } from './shared';

interface PolicyResponse {
    error?: any;
    name?: string;
    message?: string;
}

function formatErrorMessage(error: unknown): string {
    if (error === undefined || error === null || error === '') {
        return 'An unknown error occurred';
    }

    if (typeof error === 'object' && error !== null) {
        return JSON.stringify(error) || 'An unknown error occurred';
    }

    return String(error);
}

function showErrorNotification(message: string): void {
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

async function copyTextToClipboard(text: string): Promise<void> {
    if (navigator.clipboard) {
        await navigator.clipboard.writeText(text);
        return;
    }

    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', 'readonly');
    textarea.style.position = 'fixed';
    textarea.style.top = '-1000px';
    textarea.style.left = '-1000px';
    document.body.appendChild(textarea);
    textarea.select();

    try {
        if (!document.execCommand('copy')) {
            throw new Error('Clipboard copy failed');
        }
    } finally {
        textarea.remove();
    }
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


async function savePolicy(policyName: string, policyAction: string, policyData: any): Promise<PolicyResponse> {
    const url = `/admin/api/policies`;
    const method = policyAction === 'update' ? 'PUT' : 'POST';
    const body = { name: policyName, policy: policyData };

    const response = await authenticatedFetch(url, {
        method: method,
        body: body,
    });
    const jsonResponse = await response.json() as PolicyResponse;
    if (!response.ok || "error" in jsonResponse) {
        const error = jsonResponse as ErrorMessage;
        const message = formatErrorMessage(error.error);
        throw new Error(message);
    }
    console.debug!(`Policy saved successfully method=${method} name=${policyName}`);
    return jsonResponse;
}

// Form handler for policy edit page
function initPolicyForm(): void {
    const form = document.getElementById('policy-form') as HTMLFormElement | null;
    if (!form) return;

    form.addEventListener('submit', async (e: Event) => {
        console.debug("Submitting policy form");
        e.preventDefault();

        const policyNameInput = document.getElementById('policy-name') as HTMLInputElement;
        const policyJsonInput = document.getElementById('policy-json') as HTMLTextAreaElement;
        const policyActionInput = document.getElementById('policy-action') as HTMLTextAreaElement;
        // strip all non-url-safe characters from policy name for redirect
        const policyName = encodeURIComponent(policyNameInput.value);
        const policyJson = policyJsonInput.value;
        const policyAction = policyActionInput.value;

        try {
            const policyData = JSON.parse(policyJson);
            const response = await savePolicy(policyName, policyAction, policyData);
            console.debug(`Policy saved successfully: ${JSON.stringify(response)}`);
            window.location.href = `/admin/policies/view/${policyName}`;
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            console.error('Error saving policy:', error);
            showErrorNotification(message);
        }
    });
}

// Handler for policy detail page delete button
function initPolicyDetail(): void {
    const deleteBtn = document.getElementById('delete-policy-btn') as HTMLButtonElement | null;
    const copyPolicyJsonBtn = document.getElementById('copy-policy-json-btn') as HTMLButtonElement | null;
    const policyJsonCode = document.getElementById('policy-json-code') as HTMLElement | null;

    if (deleteBtn) {
        deleteBtn.addEventListener('click', (e: Event) => {
            e.preventDefault();
            const policyName = deleteBtn.dataset.policyName;
            if (policyName) {
                deletePolicy(policyName);
            }
        });
    }

    if (copyPolicyJsonBtn && policyJsonCode) {
        copyPolicyJsonBtn.addEventListener('click', async (e: Event) => {
            e.preventDefault();
            copyPolicyJsonBtn.classList.remove('copied', 'copy-failed');

            try {
                await copyTextToClipboard(policyJsonCode.textContent ?? '');
                copyPolicyJsonBtn.classList.add('copied');
            } catch (error) {
                console.error('Error copying policy JSON:', error);
                copyPolicyJsonBtn.classList.add('copy-failed');
            } finally {
                window.setTimeout(() => {
                    copyPolicyJsonBtn.classList.remove('copied', 'copy-failed');
                }, 1200);
            }
        });
    }
}

// Initialize on page load
function initPolicyPages(): void {
    const errors = document.getElementsByClassName('error-notification');
    Array.from(errors).forEach((errorNotification) => {
        console.debug(errorNotification.textContent.trim().length);
        if (errorNotification.textContent.trim().length == 0) {
            console.debug("error notification is empty");
            errorNotification.classList.add('error-notification-hide');
        } else {
            console.debug("error notification is not empty");
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
