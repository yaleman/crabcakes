// Policy CRUD operations

async function deletePolicy(policyName) {
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
        alert(`Error deleting policy: ${error.message}`);
    }
}

async function savePolicy(policyName, policyData) {
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
            const error = await response.text();
            throw new Error(`Failed to save policy: ${error}`);
        }

        const result = await response.json();
        return result;
    } catch (error) {
        console.error('Error saving policy:', error);
        throw error;
    }
}

// Form handler for policy edit page
function initPolicyForm() {
    const form = document.getElementById('policy-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const policyName = document.getElementById('policy-name').value;
        const policyJson = document.getElementById('policy-json').value;

        try {
            const policyData = JSON.parse(policyJson);
            await savePolicy(policyName, policyData);
            alert('Policy saved successfully!');
            window.location.href = `/admin/policies/${policyName}`;
        } catch (error) {
            alert(`Error: ${error.message}`);
        }
    });
}

// Handler for policy detail page delete button
function initPolicyDetail() {
    const deleteBtn = document.getElementById('delete-policy-btn');
    if (!deleteBtn) return;

    deleteBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const policyName = deleteBtn.dataset.policyName;
        deletePolicy(policyName);
    });
}

// Initialize on page load
function initPolicyPages() {
    initPolicyForm();
    initPolicyDetail();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initPolicyPages);
} else {
    initPolicyPages();
}
