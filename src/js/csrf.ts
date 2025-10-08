// CSRF token handling
let csrfToken: string | null = null;

interface CsrfTokenResponse {
    csrf_token: string;
}

async function getCsrfToken(): Promise<string> {
    if (csrfToken) {
        return csrfToken;
    }

    try {
        const response = await fetch('/admin/api/csrf-token');
        if (!response.ok) {
            throw new Error('Failed to fetch CSRF token');
        }
        const data: CsrfTokenResponse = await response.json();
        csrfToken = data.csrf_token;
        return csrfToken;
    } catch (error) {
        console.error('Error fetching CSRF token:', error);
        throw error;
    }
}

interface AuthenticatedFetchOptions extends RequestInit {
    body?: any;
}

// Helper to make authenticated requests with CSRF token
export async function authenticatedFetch(url: string, options: AuthenticatedFetchOptions = {}): Promise<Response> {
    const token = await getCsrfToken();

    const headers: HeadersInit = {
        ...options.headers,
        'X-CSRF-Token': token,
    };

    if (options.body && typeof options.body === 'object') {
        (headers as Record<string, string>)['Content-Type'] = 'application/json';
        options.body = JSON.stringify(options.body);

    }

    return fetch(url, {

        ...options,

        headers,
    });
}
