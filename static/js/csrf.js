// CSRF token handling
let csrfToken = null;

async function getCsrfToken() {
    if (csrfToken) {
        return csrfToken;
    }

    try {
        const response = await fetch('/admin/api/csrf-token');
        if (!response.ok) {
            throw new Error('Failed to fetch CSRF token');
        }
        const data = await response.json();
        csrfToken = data.csrf_token;
        return csrfToken;
    } catch (error) {
        console.error('Error fetching CSRF token:', error);
        throw error;
    }
}

// Helper to make authenticated requests with CSRF token
async function authenticatedFetch(url, options = {}) {
    const token = await getCsrfToken();

    const headers = {
        ...options.headers,
        'X-CSRF-Token': token,
    };

    if (options.body && typeof options.body === 'object') {
        headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(options.body);
    }

    return fetch(url, {
        ...options,
        headers,
    });
}
