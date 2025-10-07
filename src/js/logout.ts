// Clear credentials from localStorage on logout
const logoutForm = document.querySelector<HTMLFormElement>('form[action="/logout"]');
if (logoutForm) {
    logoutForm.addEventListener('submit', function (): void {
        localStorage.removeItem('crabcakes_access_key_id');
        localStorage.removeItem('crabcakes_secret_access_key');
        localStorage.removeItem('crabcakes_expires_at');
        localStorage.removeItem('crabcakes_user_email');
    });
}
