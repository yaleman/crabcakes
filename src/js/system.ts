import { authenticatedFetch } from './csrf.js';

// Vacuum statistics from API
interface VacuumStats {
    needs_vacuum: boolean;
    freelist_count: number;
    page_count: number;
    percentage: number;
}

// Vacuum execution response
interface VacuumResponse {
    success: boolean;
    reclaimed_pages: number;
    error?: string;
}

// Load vacuum statistics from API
async function loadVacuumStats(): Promise<void> {
    try {
        const response = await fetch('/admin/api/database/vacuum');
        if (!response.ok) {
            throw new Error('Failed to fetch vacuum stats');
        }

        const stats: VacuumStats = await response.json();
        updateUI(stats);
    } catch (error) {
        console.error('Error loading vacuum stats:', error);
        showError('Failed to load vacuum statistics');
    }
}

// Update UI with vacuum statistics
function updateUI(stats: VacuumStats): void {
    const statusBadge = document.getElementById('vacuum-status');
    const pageCount = document.getElementById('page-count');
    const freelistCount = document.getElementById('freelist-count');
    const freelistPercentage = document.getElementById('freelist-percentage');
    const vacuumBtn = document.getElementById('vacuum-btn') as HTMLButtonElement;

    if (statusBadge && pageCount && freelistCount && freelistPercentage && vacuumBtn) {
        // Update status badge
        if (stats.needs_vacuum) {
            statusBadge.textContent = 'Vacuum Recommended';
            statusBadge.className = 'badge badge-deny';
            vacuumBtn.disabled = false;
        } else {
            statusBadge.textContent = 'Healthy';
            statusBadge.className = 'badge badge-allow';
            vacuumBtn.disabled = true;
        }

        // Update stats
        pageCount.textContent = stats.page_count.toLocaleString();
        freelistCount.textContent = stats.freelist_count.toLocaleString();
        freelistPercentage.textContent = `${stats.percentage.toFixed(2)}%`;
    }
}

// Execute database vacuum
async function executeVacuum(): Promise<void> {
    const vacuumBtn = document.getElementById('vacuum-btn') as HTMLButtonElement;
    const resultDiv = document.getElementById('vacuum-result');

    if (!vacuumBtn || !resultDiv) return;

    // Disable button and show loading state
    vacuumBtn.disabled = true;
    vacuumBtn.textContent = 'Vacuuming...';
    resultDiv.style.display = 'none';

    try {
        const response = await authenticatedFetch('/admin/api/database/vacuum?confirm=true', {
            method: 'POST',
        });

        if (!response.ok) {
            throw new Error('Vacuum operation failed');
        }

        const result: VacuumResponse = await response.json();

        if (result.success) {
            showSuccess(`Vacuum completed successfully. Reclaimed ${result.reclaimed_pages} pages.`);
            // Reload stats after vacuum
            await loadVacuumStats();
        } else {
            showError(result.error || 'Vacuum operation failed');
        }
    } catch (error) {
        console.error('Error executing vacuum:', error);
        showError('Failed to execute vacuum operation');
    } finally {
        vacuumBtn.textContent = 'Vacuum Database';
    }
}

// Show success message
function showSuccess(message: string): void {
    const resultDiv = document.getElementById('vacuum-result');
    if (resultDiv) {
        resultDiv.textContent = message;
        resultDiv.className = 'message success';
        resultDiv.style.display = 'block';
    }
}

// Show error message
function showError(message: string): void {
    const resultDiv = document.getElementById('vacuum-result');
    if (resultDiv) {
        resultDiv.textContent = message;
        resultDiv.className = 'message error';
        resultDiv.style.display = 'block';
    }
}

// Initialize page
document.addEventListener('DOMContentLoaded', () => {
    // Load initial stats
    loadVacuumStats();

    // Attach vacuum button handler
    const vacuumBtn = document.getElementById('vacuum-btn');
    if (vacuumBtn) {
        vacuumBtn.addEventListener('click', executeVacuum);
    }
});
