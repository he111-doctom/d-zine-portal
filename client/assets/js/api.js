// client/assets/js/api.js
// API_BASE is now provided by config.js (loaded before this file)
const API_BASE = (typeof CONFIG !== 'undefined') ? CONFIG.API_BASE : 'http://localhost:5000/api';

// Simple API client
const api = {
    // Test connection
    async testConnection() {
        try {
            const response = await fetch(`${API_BASE}/health`);
            return await response.json();
        } catch (error) {
            console.error('API connection error:', error);
            return { error: 'Cannot connect to server' };
        }
    },
    
    // Auth endpoints
    async login(email, password) {
        try {
            const response = await fetch(`${API_BASE}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });
            return await response.json();
        } catch (error) {
            return { error: error.message };
        }
    },
    
    async register(userData) {
        try {
            const response = await fetch(`${API_BASE}/auth/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(userData)
            });
            return await response.json();
        } catch (error) {
            return { error: error.message };
        }
    },
    
    async getCurrentUser() {
        try {
            const token = localStorage.getItem('token');
            if (!token) return { error: 'No token' };
            
            const response = await fetch(`${API_BASE}/auth/me`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            return await response.json();
        } catch (error) {
            return { error: error.message };
        }
    },
    
    // Project endpoints
    async getProjects() {
        try {
            const token = localStorage.getItem('token');
            const response = await fetch(`${API_BASE}/projects`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            return await response.json();
        } catch (error) {
            return { error: error.message };
        }
    },
    
    // Questionnaire endpoints
    async saveQuestionnaire(projectId, answers) {
        try {
            const token = localStorage.getItem('token');
            const response = await fetch(`${API_BASE}/questionnaire/${projectId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ answers })
            });
            return await response.json();
        } catch (error) {
            return { error: error.message };
        }
    },
    
    async submitQuestionnaire(projectId) {
        try {
            const token = localStorage.getItem('token');
            const response = await fetch(`${API_BASE}/questionnaire/${projectId}/submit`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            return await response.json();
        } catch (error) {
            return { error: error.message };
        }
    }
};

// Auto-test connection on load
document.addEventListener('DOMContentLoaded', async () => {
    const result = await api.testConnection();
    if (result.error) {
        console.warn('⚠️ Backend not available:', result.error);
        console.warn('💡 Make sure to start the server: cd server && npm run dev');
    } else {
        console.log('✅ Backend connected:', result);
    }
});

// Make api global
window.api = api;