// Test setup file for vitest
import { vi } from 'vitest';

// Mock localStorage
const localStorageMock = {
    getItem: vi.fn(),
    setItem: vi.fn(),
    removeItem: vi.fn(),
    clear: vi.fn(),
};

global.localStorage = localStorageMock as any;

// Mock window.location
delete (window as any).location;
window.location = {
    origin: 'http://localhost:3000',
    href: 'http://localhost:3000',
    reload: vi.fn(),
} as any;

// Mock alert and confirm
global.alert = vi.fn();
global.confirm = vi.fn();

// Mock URL and URLSearchParams
global.URL = URL as any;
global.URLSearchParams = URLSearchParams as any;
