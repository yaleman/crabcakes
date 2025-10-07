/**
 * Go back one step in the browser history
 * If there's no history to go back to, redirect to the home page
 */
function goBack(): void {
    // Check if there's history to go back to
    if (window.history.length > 1) {
        window.history.back();
    } else {
        // Fallback to home page if no history available
        window.location.href = '/admin';
    }
}

// Add event listener when the DOM is loaded
document.addEventListener('DOMContentLoaded', function (): void {
    const backButton = document.getElementById('back-button') as HTMLAnchorElement | null;
    if (backButton) {
        backButton.addEventListener('click', goBack);
        backButton.href = "#"; // Prevent default link behavior
    }
});
