/**
 * D'zine Brand Studio - Client Config
 * Change API_BASE to your production URL before deploying.
 * e.g. 'https://api.yourserver.com/api'
 */
const CONFIG = {
    API_BASE: (function() {
        // Auto-detect: if opening from file:// or localhost, use localhost backend
        const host = window.location.hostname;
        if (host === 'localhost' || host === '127.0.0.1' || host === '') {
            return 'http://localhost:5000/api';
        }
        // Production — same origin (served by Express static) or custom domain
        return window.location.origin + '/api';
    })()
};

// Freeze so nothing accidentally overwrites it
Object.freeze(CONFIG);
