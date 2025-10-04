// Fetch full credentials from API and store in localStorage
fetch('/api/session')
    .then(response => {
        if (!response.ok) {
            throw new Error('Failed to fetch credentials');
        }
        return response.json();
    })
    .then(data => {
        // Store credentials in localStorage
        localStorage.setItem('crabcakes_access_key_id', data.access_key_id);
        localStorage.setItem('crabcakes_secret_access_key', data.secret_access_key);
        localStorage.setItem('crabcakes_expires_at', data.expires_at);
        localStorage.setItem('crabcakes_user_email', data.user_email);
        console.log('Credentials stored in localStorage');
    })
    .catch(error => {
        console.error('Error fetching credentials:', error);
    });
