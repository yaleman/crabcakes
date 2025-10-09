

// Session data structure
interface SessionData {
    access_key_id: string;
    secret_access_key: string;
    expires_at: string;
    user_email: string;
}

// Fetch credentials from API and store in localStorage

async function sessionCredentials(): Promise<SessionData | null> {
    return fetch('/admin/api/session')
        .then((response: Response) => {
            if (!response.ok) {
                throw new Error('Failed to fetch credentials');
            }
            return response.json();
        })
        .then((data: SessionData) => {
            return data
        })
        .catch((error: Error) => {
            console.error('Error fetching credentials:', error);
            return null
        });
}


interface ErrorMessage {
    error?: string;
    success?: boolean;
}

export { sessionCredentials, SessionData, ErrorMessage }
