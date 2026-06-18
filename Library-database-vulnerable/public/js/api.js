// API Configuration
const API_BASE_URL = '/api';

// API Helper Functions
const API = {
    // ==================== BOOKS ====================
    async getBooks() {
        const response = await fetch(`${API_BASE_URL}/books`);
        return response.json();
    },

    async addBook(bookData) {
        const response = await fetch(`${API_BASE_URL}/books`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(bookData)
        });
        return response.json();
    },

    async updateBook(bookId, bookData) {
        const response = await fetch(`${API_BASE_URL}/books/${bookId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(bookData)
        });
        return response.json();
    },

    async deleteBook(bookId) {
        const response = await fetch(`${API_BASE_URL}/books/${bookId}`, {
            method: 'DELETE'
        });
        return response.json();
    },

    async searchBooks(title) {
        const response = await fetch(`${API_BASE_URL}/books/search/${encodeURIComponent(title)}`);
        return response.json();
    },

    // ==================== MEMBERS ====================
    async getMembers() {
        const response = await fetch(`${API_BASE_URL}/members`);
        return response.json();
    },

    async addMember(memberData) {
        const response = await fetch(`${API_BASE_URL}/members`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(memberData)
        });
        return response.json();
    },

    async updateMember(memberId, memberData) {
        const response = await fetch(`${API_BASE_URL}/members/${memberId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(memberData)
        });
        return response.json();
    },

    async deleteMember(memberId) {
        const response = await fetch(`${API_BASE_URL}/members/${memberId}`, {
            method: 'DELETE'
        });
        return response.json();
    },

    async searchMembers(name) {
        const response = await fetch(`${API_BASE_URL}/members/search/${encodeURIComponent(name)}`);
        return response.json();
    },

    // ==================== AUTHORS ====================
    async getAuthors() {
        const response = await fetch(`${API_BASE_URL}/authors`);
        return response.json();
    },

    async addAuthor(authorData) {
        const response = await fetch(`${API_BASE_URL}/authors`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(authorData)
        });
        return response.json();
    },

    async updateAuthor(authorId, authorData) {
        const response = await fetch(`${API_BASE_URL}/authors/${authorId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(authorData)
        });
        return response.json();
    },

    async deleteAuthor(authorId) {
        const response = await fetch(`${API_BASE_URL}/authors/${authorId}`, {
            method: 'DELETE'
        });
        return response.json();
    },

    async searchAuthors(name) {
        const response = await fetch(`${API_BASE_URL}/authors/search/${encodeURIComponent(name)}`);
        return response.json();
    },

    // ==================== PUBLISHERS ====================
    async getPublishers() {
        const response = await fetch(`${API_BASE_URL}/publishers`);
        return response.json();
    },

    async addPublisher(publisherData) {
        const response = await fetch(`${API_BASE_URL}/publishers`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(publisherData)
        });
        return response.json();
    },

    async updatePublisher(publisherId, publisherData) {
        const response = await fetch(`${API_BASE_URL}/publishers/${publisherId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(publisherData)
        });
        return response.json();
    },

    async deletePublisher(publisherId) {
        const response = await fetch(`${API_BASE_URL}/publishers/${publisherId}`, {
            method: 'DELETE'
        });
        return response.json();
    },

    async searchPublishers(name) {
        const response = await fetch(`${API_BASE_URL}/publishers/search/${encodeURIComponent(name)}`);
        return response.json();
    },

    // ==================== USERS ====================
    async getUsers() {
        const response = await fetch(`${API_BASE_URL}/users`);
        return response.json();
    },

    async addUser(userData) {
        const response = await fetch(`${API_BASE_URL}/users`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(userData)
        });
        return response.json();
    },

    async updateUser(userId, userData) {
        const response = await fetch(`${API_BASE_URL}/users/${userId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(userData)
        });
        return response.json();
    },

    async deleteUser(userId) {
        const response = await fetch(`${API_BASE_URL}/users/${userId}`, {
            method: 'DELETE'
        });
        return response.json();
    },

    async searchUsers(username) {
        const response = await fetch(`${API_BASE_URL}/users/search/${encodeURIComponent(username)}`);
        return response.json();
    },

    // ==================== BORROWING ====================
    async getBorrowing() {
        const response = await fetch(`${API_BASE_URL}/borrowing`);
        return response.json();
    },

    async borrowBook(borrowData) {
        const response = await fetch(`${API_BASE_URL}/borrowing`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(borrowData)
        });
        return response.json();
    },

    async returnBook(borrowId, returnData) {
        const response = await fetch(`${API_BASE_URL}/borrowing/return/${borrowId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(returnData)
        });
        return response.json();
    },

    async searchBorrowing(title) {
        const response = await fetch(`${API_BASE_URL}/borrowing/search/${encodeURIComponent(title)}`);
        return response.json();
    },

    // ==================== AVAILABILITY ====================
    async checkAvailability(bookName) {
        const response = await fetch(`${API_BASE_URL}/availability/search/${encodeURIComponent(bookName)}`);
        return response.json();
    },

    // ==================== FINES ====================
    async getFines() {
        const response = await fetch(`${API_BASE_URL}/fines`);
        return response.json();
    },

    async addFine(fineData) {
        const response = await fetch(`${API_BASE_URL}/fines`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(fineData)
        });
        return response.json();
    },

    async updateFine(fineId, fineData) {
        const response = await fetch(`${API_BASE_URL}/fines/${fineId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(fineData)
        });
        return response.json();
    },

    async deleteFine(fineId) {
        const response = await fetch(`${API_BASE_URL}/fines/${fineId}`, {
            method: 'DELETE'
        });
        return response.json();
    },

    async searchFines(borrowId) {
        const response = await fetch(`${API_BASE_URL}/fines/search/${encodeURIComponent(borrowId)}`);
        return response.json();
    },

    // ==================== REPORTS ====================
    async getReportMostBorrowed() {
        const response = await fetch(`${API_BASE_URL}/reports/most-borrowed`);
        return response.json();
    },

    async getReportOverdue() {
        const response = await fetch(`${API_BASE_URL}/reports/overdue`);
        return response.json();
    },

    async getReportCurrentBorrowed() {
        const response = await fetch(`${API_BASE_URL}/reports/current-borrowed`);
        return response.json();
    },

    async getReportInventory() {
        const response = await fetch(`${API_BASE_URL}/reports/inventory`);
        return response.json();
    },

    // ==================== GENRES & COPIES ====================
    async getGenres() {
        const response = await fetch(`${API_BASE_URL}/genres`);
        return response.json();
    },

    async getCopies() {
        const response = await fetch(`${API_BASE_URL}/copies`);
        return response.json();
    }
};

// ==================== Toast Notifications ====================
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    let icon;
    switch (type) {
        case 'success':
            icon = 'fa-check-circle';
            break;
        case 'error':
            icon = 'fa-exclamation-circle';
            break;
        case 'warning':
            icon = 'fa-exclamation-triangle';
            break;
        default:
            icon = 'fa-info-circle';
    }
    
    toast.innerHTML = `
        <i class="fas ${icon}"></i>
        <span>${message}</span>
    `;
    
    container.appendChild(toast);
    
    // Auto remove after 4 seconds
    setTimeout(() => {
        toast.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ==================== Utility Functions ====================
function formatCurrency(value) {
    return '$' + parseFloat(value || 0).toFixed(2);
}

function formatDate(dateString) {
    if (!dateString) return '';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}
