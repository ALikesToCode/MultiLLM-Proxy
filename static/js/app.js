function registerServiceWorker() {
    if (!('serviceWorker' in navigator)) {
        return;
    }

    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/service-worker.js').catch((err) => {
            console.error('Service worker registration failed:', err);
        });
    });
}

function fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    const copied = document.execCommand('copy');
    textarea.remove();
    return copied;
}

async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
    }
    return fallbackCopy(text);
}

function showToast(message, type = 'success') {
    const region = document.getElementById('toast-region');
    if (!region) {
        return;
    }

    const toast = document.createElement('div');
    toast.className = type === 'error' ? 'toast toast--error' : 'toast';
    toast.textContent = message;
    region.appendChild(toast);
    window.setTimeout(() => toast.remove(), 3200);
}

function initializeMobileNavigation() {
    const menuButton = document.getElementById('mobile-menu-button');
    const mobileMenu = document.getElementById('mobile-menu');
    if (!menuButton || !mobileMenu) {
        return;
    }

    menuButton.addEventListener('click', () => {
        const expanded = menuButton.getAttribute('aria-expanded') === 'true';
        menuButton.setAttribute('aria-expanded', String(!expanded));
        mobileMenu.hidden = expanded;
    });
}

function initializeCopyButtons() {
    document.addEventListener('click', async (event) => {
        const button = event.target.closest('[data-copy-value]');
        if (!button) {
            return;
        }
        const value = button.getAttribute('data-copy-value') || '';
        try {
            await copyText(value);
            showToast('Copied to clipboard');
        } catch (error) {
            console.error('Clipboard copy failed:', error);
            showToast('Could not copy to clipboard', 'error');
        }
    });
}

document.addEventListener('DOMContentLoaded', () => {
    initializeMobileNavigation();
    initializeCopyButtons();
    registerServiceWorker();
});

window.MultiLLM = Object.freeze({
    copyText,
    showToast
});
