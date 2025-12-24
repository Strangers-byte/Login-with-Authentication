const API_BASE_URL = 'http://localhost:8000/api';

let refreshTimeout;
let authCheckInterval = null; // Properly declare this

// APIError class
class APIError extends Error {
    constructor(message, status) {
        super(message);
        this.status = status;
    }
}

// Header management functions
const HeaderManager = {
    async loadAppropriateHeader() {
        const token = localStorage.getItem('access_token');
        
        if (token) {
            await this.loadHeader('./headerLoggedIn.html');
            this.addHeaderEventListeners();
        } else {
            await this.loadHeader('./header.html');
        }
    },

    async loadHeader(url) {
        try {
            console.log('Loading header from:', url);
            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`Failed to load header: ${response.status}`);
            }
            
            const html = await response.text();
            console.log('Header HTML received:', html.substring(0, 200) + '...');
            
            const headerContainer = document.getElementById('header-container');
            
            if (headerContainer) {
                console.log('Header container found, updating content');
                headerContainer.innerHTML = html;
                
                // Check if the header content is actually visible
                setTimeout(() => {
                    console.log('Header container after update:', headerContainer.innerHTML.substring(0, 200) + '...');
                }, 100);
            } else {
                console.error('Header container not found');
            }
        } catch (err) {
            console.error('Error loading header:', err);
            // Fallback code...
        }
    },
    
    addHeaderEventListeners() {
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', async function(e) {
                e.preventDefault();
                try {
                    await authAPI.logout();
                    await HeaderManager.loadAppropriateHeader();
                    showAlert('Logged out successfully', 'success');
                } catch (error) {
                    console.error('Logout error:', error);
                    showAlert('Logout failed', 'error');
                }
            });
        }
    }
};

function scheduleTokenRefresh(expiresIn) {
    clearTimeout(refreshTimeout);
    if (!expiresIn || expiresIn <= 0) expiresIn = 900;

    const refreshTime = (expiresIn - 60) * 1000;
    console.log(`Scheduling token refresh in ${refreshTime/1000} seconds`);

    refreshTimeout = setTimeout(async () => {
        try {
            console.log('Attempting automatic token refresh...');
            await authAPI.refreshToken();
            console.log('Token refreshed successfully');
            scheduleTokenRefresh(expiresIn);
        } catch (error) {
            console.error('Token refresh failed:', error);
            showAlert('Your session has expired. Please login again.', 'error');
            await authAPI.logout();
            updateUIForAuthState(false);
        }
    }, refreshTime);
}

async function handleResponse(response) {
    if (!response.ok) {
        let errorData;
        try {
            errorData = await response.json();
        } catch (jsonError) {
            const errorText = await response.text();
            errorData = { detail: errorText || 'API request failed' };
        }
        throw new APIError(errorData.detail || 'API request failed', response.status);
    }
    
    try {
        return await response.json();
    } catch (jsonError) {
        throw new APIError('Invalid response from server', response.status);
    }
}

function setElementText(id, text) {
    const element = document.getElementById(id);
    if (element) element.textContent = text;
}

async function getUserData() {
    const token = localStorage.getItem('access_token');
    if (!token) return null;
    
    try {
        const response = await fetch(`${API_BASE_URL}/me`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            if (response.status === 401) {
                console.log('Token expired in getUserData');
                return null;
            }
            throw new Error('Failed to fetch user data');
        }

        return await response.json();
    } catch (error) {
        console.error('Error fetching user data:', error);
        return null;
    }
}

const authAPI = {
    async register(userData) {
        const response = await fetch(`${API_BASE_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(userData)
        });
        return await handleResponse(response);
    },

    async login(credentials) {
        const formData = new URLSearchParams();
        formData.append('username', credentials.username);
        formData.append('password', credentials.password);

        const response = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: formData
        });
        
        const data = await handleResponse(response);
        localStorage.setItem('access_token', data.access_token);
        if (data.refresh_token) {
            localStorage.setItem('refresh_token', data.refresh_token);
        }
        
        await HeaderManager.loadAppropriateHeader();
        return data;
    },

    async logout() {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        await HeaderManager.loadAppropriateHeader();
    },

    async refreshToken() {
        const refreshToken = localStorage.getItem('refresh_token');
        if (!refreshToken) throw new Error('No refresh token available');

        const response = await fetch(`${API_BASE_URL}/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: refreshToken })
        });
        
        const data = await handleResponse(response);
        localStorage.setItem('access_token', data.access_token);
        return data;
    }
};

async function handleLogout() {
    try {
        await authAPI.logout();
        window.location.href = 'login.html';
    } catch (error) {
        console.error('Logout error:', error);
        window.location.href = 'login.html';
    }
}

const AuthSystem = (function() {
    let currentUser = null;

    function isAuthPage() {
        const authPages = ['login.html', 'register.html', 'forgot-password.html', 'reset-password.html'];
        const currentPage = window.location.pathname.split('/').pop();
        return authPages.includes(currentPage);
    }

    function init() {
        setupForms();
        
        // ONLY check auth on non-auth pages
        if (!isAuthPage()) {
            checkAuthState();
            startAuthCheckInterval();
        }
        
        HeaderManager.loadAppropriateHeader();
    }

    async function checkAuthState() {   
        try {
            const token = localStorage.getItem('access_token');
            if (token) {
                updateUIForAuthState(true);
            }
        } catch (error) {
            console.error('Auth check failed:', error);
        }
    }

    function setupForms() {
        document.querySelectorAll('#signup-form').forEach(form => {
            form.addEventListener('submit', handleSignup);
        });

        document.querySelectorAll('form[data-auth="login"]').forEach(form => {
            form.addEventListener('submit', handleLogin);
        });

        document.querySelectorAll('[data-auth="logout"]').forEach(button => {
            button.addEventListener('click', handleLogout);
        });
    }

    async function handleSignup(e) {
        e.preventDefault();
        const form = e.target;
        
        const formData = {
            username: form.querySelector('[name="username"]').value.trim(),
            email: form.querySelector('[name="email"]').value.trim().toLowerCase(),
            password: form.querySelector('[name="password"]').value,
            full_name: form.querySelector('[name="full_name"]').value.trim()
        };

        try {
            showLoading(true, form);
            await authAPI.register(formData);
            showAlert('Account created successfully! Please login.', 'success');
            form.reset();
            redirectAfterDelay('login.html', 1500);
        } catch (error) {
            showAlert(error.message || 'Registration failed', 'error');
        } finally {
            showLoading(false, form);
        }
    }

    async function handleLogin(e) {
        e.preventDefault();
        const form = e.target;
        
        const credentials = {
            username: form.querySelector('[name="username"]').value.trim(),
            password: form.querySelector('[name="password"]').value
        };

        try {
            showLoading(true, form);
            await authAPI.login(credentials);
            showAlert('Login successful!', 'success');
            updateUIForAuthState(true);
            redirectAfterDelay('index.html', 1000);
        } catch (error) {
            showAlert(getLoginErrorMessage(error), 'error');
        } finally {
            showLoading(false, form);
        }
    }

    function getLoginErrorMessage(error) {
        if (error instanceof APIError) {
            switch (error.status) {
                case 401: return 'Invalid username or password';
                default: return 'Login failed';
            }
        }
        return error.message || 'Login failed';
    }

    function startAuthCheckInterval() {
        clearInterval(authCheckInterval);
        
        // DISABLE automatic token refresh to prevent loops
        console.log('Auth check interval started (refresh disabled to prevent loops)');
        
        // Optional: Keep the interval but don't do anything aggressive
        authCheckInterval = setInterval(() => {
            // Just log that we're running, no automatic refresh
            console.log('Auth check interval running (refresh disabled)');
        }, 300000); // Check every 5 minutes
    }

    function updateUIForAuthState(isAuthenticated) {
        console.log('Updating UI for auth state:', isAuthenticated);
        
        // Update authenticated elements
        document.querySelectorAll('[data-auth-state="authenticated"]').forEach(el => {
            el.style.display = isAuthenticated ? 'block' : 'none';
            console.log('Setting authenticated element display:', el.style.display);
        });
        
        // Update anonymous elements
        document.querySelectorAll('[data-auth-state="anonymous"]').forEach(el => {
            el.style.display = isAuthenticated ? 'none' : 'block';
            console.log('Setting anonymous element display:', el.style.display);
        });
        
        // If authenticated, try to load user data
        if (isAuthenticated) {
            getUserData().then(userData => {
                if (userData) {
                    console.log('User data loaded:', userData);
                    document.querySelectorAll('[data-user="fullname"]').forEach(el => {
                        el.textContent = userData.full_name || 'User';
                        console.log('Set user fullname:', el.textContent);
                    });
                    
                    document.querySelectorAll('[data-user="username"]').forEach(el => {
                        el.textContent = userData.username || 'user';
                        console.log('Set username:', el.textContent);
                    });
                }
            }).catch(error => {
                console.error('Failed to load user data:', error);
            });
        }
    }

    function showLoading(show, form) {
        const buttons = form.querySelectorAll('button[type="submit"]');
        buttons.forEach(button => {
            button.disabled = show;
            const loader = button.querySelector('.loader') || document.createElement('span');
            loader.className = 'loader';
            loader.textContent = show ? '...' : '';
            if (show && !button.querySelector('.loader')) {
                button.appendChild(loader);
            } else if (!show) {
                button.querySelector('.loader')?.remove();
            }
        });
    }

    function showAlert(message, type = 'info') {
        const alertBox = document.createElement('div');
        alertBox.className = `alert ${type}`;
        alertBox.textContent = message;
        document.body.appendChild(alertBox);
        setTimeout(() => alertBox.remove(), 5000);
    }

    function redirectAfterDelay(url, delay) {
        setTimeout(() => window.location.href = url, delay);
    }

    return {
        init,
        getCurrentUser: () => currentUser,
        logout: handleLogout
    };
})();

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    AuthSystem.init();
});