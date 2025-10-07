// Session data structure
interface SessionData {
    access_key_id: string;
    secret_access_key: string;
    expires_at: string;
    user_email: string;
}

// Fetch full credentials from API and store in localStorage
fetch('/api/session')
    .then((response: Response) => {
        if (!response.ok) {
            throw new Error('Failed to fetch credentials');
        }
        return response.json();
    })
    .then((data: SessionData) => {
        // Store credentials in localStorage
        localStorage.setItem('crabcakes_access_key_id', data.access_key_id);
        localStorage.setItem('crabcakes_secret_access_key', data.secret_access_key);
        localStorage.setItem('crabcakes_expires_at', data.expires_at);
        localStorage.setItem('crabcakes_user_email', data.user_email);
        console.debug('Credentials stored in localStorage');
    })
    .catch((error: Error) => {
        console.error('Error fetching credentials:', error);
    });
