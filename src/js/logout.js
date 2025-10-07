// Clear credentials from localStorage on logout
document.querySelector('form[action="/logout"]').addEventListener('submit', function() {
    localStorage.removeItem('crabcakes_access_key_id');
    localStorage.removeItem('crabcakes_secret_access_key');
    localStorage.removeItem('crabcakes_expires_at');
    localStorage.removeItem('crabcakes_user_email');
});
