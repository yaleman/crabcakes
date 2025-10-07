import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { S3Client } from '@aws-sdk/client-s3';

// Mock the S3 SDK
vi.mock('@aws-sdk/client-s3', () => ({
    S3Client: vi.fn(() => ({
        send: vi.fn(),
    })),
    GetObjectCommand: vi.fn(),
    DeleteObjectCommand: vi.fn(),
    DeleteObjectsCommand: vi.fn(),
}));

describe('Bucket Operations', () => {
    beforeEach(() => {
        // Reset all mocks before each test
        vi.clearAllMocks();
        document.body.innerHTML = '';

        // Setup localStorage mocks
        (localStorage.getItem as any).mockImplementation((key: string) => {
            if (key === 'crabcakes_access_key_id') return 'test-access-key';
            if (key === 'crabcakes_secret_access_key') return 'test-secret-key';
            return null;
        });

        // Reset window mocks
        (window.location.reload as any).mockClear();
        (global.alert as any).mockClear();
        (global.confirm as any).mockClear();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe('downloadObject', () => {
        it('should create S3 client with credentials from localStorage', async () => {
            // This test verifies the getS3Client function works correctly
            const { S3Client: MockS3Client } = await import('@aws-sdk/client-s3');

            // Import the module to trigger client creation
            await import('../bucket-operations');

            // Trigger a download to create the client
            const downloadBtn = document.createElement('button');
            downloadBtn.className = 'download-object-btn';
            downloadBtn.dataset.bucket = 'test-bucket';
            downloadBtn.dataset.key = 'test-file.txt';
            document.body.appendChild(downloadBtn);

            // Re-initialize after DOM setup
            const event = new Event('click');
            downloadBtn.dispatchEvent(event);

            expect(localStorage.getItem).toHaveBeenCalledWith('crabcakes_access_key_id');
            expect(localStorage.getItem).toHaveBeenCalledWith('crabcakes_secret_access_key');
        });

        it('should throw error if credentials are missing', async () => {
            (localStorage.getItem as any).mockReturnValue(null);

            const downloadBtn = document.createElement('button');
            downloadBtn.className = 'download-object-btn';
            downloadBtn.dataset.bucket = 'test-bucket';
            downloadBtn.dataset.key = 'test-file.txt';
            document.body.appendChild(downloadBtn);

            downloadBtn.click();

            // Should show alert with error
            await vi.waitFor(() => {
                expect(global.alert).toHaveBeenCalledWith(
                    expect.stringContaining('No credentials found')
                );
            });
        });
    });

    describe('deleteObject', () => {
        it('should ask for confirmation before deleting', async () => {
            (global.confirm as any).mockReturnValue(false);

            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'delete-object-btn';
            deleteBtn.dataset.bucket = 'test-bucket';
            deleteBtn.dataset.key = 'test-file.txt';
            document.body.appendChild(deleteBtn);

            deleteBtn.click();

            expect(global.confirm).toHaveBeenCalledWith(
                'Are you sure you want to delete "test-file.txt"?'
            );
        });

        it('should not delete if user cancels confirmation', async () => {
            (global.confirm as any).mockReturnValue(false);

            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'delete-object-btn';
            deleteBtn.dataset.bucket = 'test-bucket';
            deleteBtn.dataset.key = 'test-file.txt';
            document.body.appendChild(deleteBtn);

            deleteBtn.click();

            expect(window.location.reload).not.toHaveBeenCalled();
        });
    });

    describe('toggleObjectSelection', () => {
        it('should update selection counter when checkbox is toggled', async () => {
            // Setup DOM
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'object-checkbox';
            checkbox.dataset.bucket = 'test-bucket';
            checkbox.dataset.key = 'test-file.txt';

            const counter = document.createElement('span');
            counter.id = 'selection-counter';

            const bulkDeleteBtn = document.createElement('button');
            bulkDeleteBtn.id = 'bulk-delete-btn';

            document.body.appendChild(checkbox);
            document.body.appendChild(counter);
            document.body.appendChild(bulkDeleteBtn);

            // Import and initialize after DOM is ready
            const module = await import('../bucket-operations');

            // Simulate checkbox change
            checkbox.checked = true;
            const changeEvent = new Event('change');
            checkbox.dispatchEvent(changeEvent);

            // The counter should be updated
            await vi.waitFor(() => {
                expect(counter.textContent).toBe('1 item selected');
            });

            expect(bulkDeleteBtn.disabled).toBe(false);
        });

        it('should handle multiple selections', async () => {
            // Setup DOM
            const checkbox1 = document.createElement('input');
            checkbox1.type = 'checkbox';
            checkbox1.className = 'object-checkbox';
            checkbox1.dataset.bucket = 'test-bucket';
            checkbox1.dataset.key = 'file1.txt';

            const checkbox2 = document.createElement('input');
            checkbox2.type = 'checkbox';
            checkbox2.className = 'object-checkbox';
            checkbox2.dataset.bucket = 'test-bucket';
            checkbox2.dataset.key = 'file2.txt';

            const counter = document.createElement('span');
            counter.id = 'selection-counter';

            const bulkDeleteBtn = document.createElement('button');
            bulkDeleteBtn.id = 'bulk-delete-btn';

            document.body.appendChild(checkbox1);
            document.body.appendChild(checkbox2);
            document.body.appendChild(counter);
            document.body.appendChild(bulkDeleteBtn);

            // Import and initialize
            await import('../bucket-operations');

            // Check both
            checkbox1.checked = true;
            checkbox1.dispatchEvent(new Event('change'));

            checkbox2.checked = true;
            checkbox2.dispatchEvent(new Event('change'));

            await vi.waitFor(() => {
                expect(counter.textContent).toBe('2 items selected');
            });
        });
    });

    describe('toggleSelectAll', () => {
        it('should select all checkboxes when select-all is checked', async () => {
            // Setup DOM
            const selectAll = document.createElement('input');
            selectAll.type = 'checkbox';
            selectAll.id = 'select-all';

            const checkbox1 = document.createElement('input');
            checkbox1.type = 'checkbox';
            checkbox1.className = 'object-checkbox';
            checkbox1.dataset.bucket = 'test-bucket';
            checkbox1.dataset.key = 'file1.txt';

            const checkbox2 = document.createElement('input');
            checkbox2.type = 'checkbox';
            checkbox2.className = 'object-checkbox';
            checkbox2.dataset.bucket = 'test-bucket';
            checkbox2.dataset.key = 'file2.txt';

            const counter = document.createElement('span');
            counter.id = 'selection-counter';

            const bulkDeleteBtn = document.createElement('button');
            bulkDeleteBtn.id = 'bulk-delete-btn';

            document.body.appendChild(selectAll);
            document.body.appendChild(checkbox1);
            document.body.appendChild(checkbox2);
            document.body.appendChild(counter);
            document.body.appendChild(bulkDeleteBtn);

            // Import and initialize
            await import('../bucket-operations');

            // Check select all
            selectAll.checked = true;
            selectAll.dispatchEvent(new Event('change'));

            await vi.waitFor(() => {
                expect(checkbox1.checked).toBe(true);
                expect(checkbox2.checked).toBe(true);
                expect(counter.textContent).toBe('2 items selected');
            });
        });
    });

    describe('deleteBatchObjects', () => {
        it('should ask for confirmation before batch delete', async () => {
            (global.confirm as any).mockReturnValue(false);

            // Setup DOM
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'object-checkbox';
            checkbox.dataset.bucket = 'test-bucket';
            checkbox.dataset.key = 'file1.txt';
            checkbox.checked = true;

            const bulkDeleteBtn = document.createElement('button');
            bulkDeleteBtn.id = 'bulk-delete-btn';

            const counter = document.createElement('span');
            counter.id = 'selection-counter';

            document.body.appendChild(checkbox);
            document.body.appendChild(bulkDeleteBtn);
            document.body.appendChild(counter);

            // Import and initialize
            await import('../bucket-operations');

            // Trigger selection
            checkbox.dispatchEvent(new Event('change'));

            // Click bulk delete
            bulkDeleteBtn.click();

            await vi.waitFor(() => {
                expect(global.confirm).toHaveBeenCalledWith(
                    'Are you sure you want to delete 1 object?'
                );
            });
        });
    });
});
