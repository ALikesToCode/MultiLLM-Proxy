/**
 * MultiLLM Proxy - Main Application Script
 * Contains shared functionality used across the application
 */

// Wait for Vue to be loaded
function initializeVue() {
    if (typeof Vue === 'undefined') {
        console.error('Vue is not loaded yet. Retrying in 100ms...');
        setTimeout(initializeVue, 100);
        return;
    }

    try {
        var pageData = {};
        var pageMethods = {};

        if (window.pageApp) {
            if (typeof window.pageApp.data === 'function') {
                try {
                    pageData = window.pageApp.data();
                } catch (err) {
                    console.error('Error initializing page data:', err);
                    pageData = {};
                }
            }
            if (window.pageApp.methods) {
                pageMethods = window.pageApp.methods;
            }
        }

        const app = Vue.createApp({
            data() {
                return Object.assign({}, pageData);
            },
            methods: Object.assign({}, pageMethods),
            mounted() {
                // Remove v-cloak when Vue is mounted
                this.$el.removeAttribute('v-cloak');
            }
        });
        
        app.mount('#app');
    } catch (err) {
        console.error('Error initializing Vue application:', err);
    }
}

// Start initialization when DOM is loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeVue);
} else {
    initializeVue();
}

// Copy text to clipboard
function copyToClipboard(button) {
    const textToCopy = button.getAttribute('data-value');
    const tempInput = document.createElement('input');
    tempInput.value = textToCopy;
    document.body.appendChild(tempInput);
    tempInput.select();
    document.execCommand('copy');
    document.body.removeChild(tempInput);
    
    // Change button text temporarily to indicate success
    const originalHTML = button.innerHTML;
    button.innerHTML = '<i class="fas fa-check mr-1"></i> Copied!';
    button.classList.remove('bg-indigo-100', 'hover:bg-indigo-200', 'text-indigo-700');
    button.classList.add('bg-green-100', 'hover:bg-green-200', 'text-green-700');
    
    setTimeout(() => {
        button.innerHTML = originalHTML;
        button.classList.remove('bg-green-100', 'hover:bg-green-200', 'text-green-700');
        button.classList.add('bg-indigo-100', 'hover:bg-indigo-200', 'text-indigo-700');
    }, 2000);
}

// Toggle password/API key visibility
function toggleVisibility(inputId, buttonSelector) {
    const input = document.getElementById(inputId);
    const button = document.querySelector(buttonSelector);
    
    if (input.type === 'password') {
        input.type = 'text';
        button.innerHTML = '<i class="fas fa-eye-slash"></i>';
    } else {
        input.type = 'password';
        button.innerHTML = '<i class="fas fa-eye"></i>';
    }
}

// Mobile menu toggle
document.addEventListener('DOMContentLoaded', function() {
    const menuButton = document.getElementById('mobile-menu-button');
    const mobileMenu = document.getElementById('mobile-menu');
    
    if (menuButton && mobileMenu) {
        menuButton.addEventListener('click', function() {
            const expanded = this.getAttribute('aria-expanded') === 'true';
            this.setAttribute('aria-expanded', !expanded);
            mobileMenu.classList.toggle('hidden');
        });
    }
    
    // Setup tooltips
    setupTooltips();
});

// Simple tooltip functionality
function setupTooltips() {
    const tooltips = document.querySelectorAll('[data-tooltip]');
    
    tooltips.forEach(tooltip => {
        tooltip.addEventListener('mouseenter', function() {
            const tooltipText = this.getAttribute('data-tooltip');
            const tooltipEl = document.createElement('div');
            tooltipEl.className = 'tooltip absolute z-50 bg-gray-800 text-white text-xs rounded py-1 px-2 -mt-8';
            tooltipEl.textContent = tooltipText;
            tooltipEl.style.transform = 'translateX(-50%)';
            
            this.appendChild(tooltipEl);
            this.style.position = 'relative';
        });
        
        tooltip.addEventListener('mouseleave', function() {
            const tooltipEl = this.querySelector('.tooltip');
            if (tooltipEl) {
                tooltipEl.remove();
            }
        });
    });
}

// Show toast notification
function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `fixed bottom-4 right-4 px-4 py-2 rounded-lg shadow-lg z-50 transform transition-all duration-300 translate-y-10 opacity-0 ${
        type === 'success' ? 'bg-green-500 text-white' : 
        type === 'error' ? 'bg-red-500 text-white' : 
        'bg-blue-500 text-white'
    }`;
    toast.textContent = message;
    
    document.body.appendChild(toast);
    
    // Animate in
    setTimeout(() => {
        toast.classList.remove('translate-y-10', 'opacity-0');
    }, 10);
    
    // Animate out and remove
    setTimeout(() => {
        toast.classList.add('translate-y-10', 'opacity-0');
        setTimeout(() => {
            toast.remove();
        }, 300);
    }, 3000);
} 