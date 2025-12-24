// api.js - Enhanced API communication handler
const API_BASE_URL = 'http://localhost:8000/api'; // Update with your FastAPI server URL

class APIError extends Error {
    constructor(message, status) {
        super(message);
        this.status = status;
    }
}

async function handleResponse(response) {
    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new APIError(
            errorData.detail || 'API request failed',
            response.status
        );
    }
    return response.json();
}

