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
    try {
        return document.execCommand('copy');
    } finally {
        textarea.remove();
    }
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
    window.setTimeout(() => toast.remove(), type === 'error' ? 6000 : 3200);
}

function copySource(button) {
    const value = button.getAttribute('data-copy-value');
    if (value !== null) {
        return { text: value, target: null };
    }
    const target = document.getElementById(button.getAttribute('data-copy-target') || '');
    return { text: target ? (target.value ?? target.textContent ?? '') : '', target };
}

function selectContents(target) {
    if (!target) {
        return;
    }
    if (typeof target.select === 'function') {
        target.focus();
        target.select();
        return;
    }
    const range = document.createRange();
    range.selectNodeContents(target);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
}

function showCopyState(button, state) {
    if (typeof button.setAttribute !== 'function') {
        return;
    }
    const label = button.getAttribute('data-copy-label') || button.textContent;
    button.setAttribute('data-copy-label', label);
    button.setAttribute('data-copy-state', state);
    button.textContent = state === 'copied' ? 'Copied' : 'Copy failed';
    window.clearTimeout(button.copyResetTimer);
    button.copyResetTimer = window.setTimeout(() => {
        button.removeAttribute('data-copy-state');
        button.textContent = label;
    }, 2000);
}

function initializeCopyButtons() {
    document.addEventListener('click', async (event) => {
        const button = event.target.closest('[data-copy-value], [data-copy-target]');
        if (!button) {
            return;
        }
        const { text, target } = copySource(button);
        try {
            if (!await copyText(text)) throw new Error('Clipboard copy was rejected');
            showCopyState(button, 'copied');
            showToast(button.getAttribute('data-copy-message') || 'Copied to clipboard');
        } catch (error) {
            console.error('Clipboard copy failed:', error);
            showCopyState(button, 'failed');
            selectContents(target);
            showToast(target
                ? 'Could not copy automatically. The text is selected; copy it manually.'
                : 'Could not copy to clipboard', 'error');
        }
    });
}

function initializeMobileNavigation() {
    const menuButton = document.getElementById('mobile-menu-button');
    const mobileMenu = document.getElementById('mobile-menu');
    if (!menuButton || !mobileMenu) {
        return;
    }

    const setOpen = (open, { restoreFocus = false } = {}) => {
        menuButton.setAttribute('aria-expanded', String(open));
        mobileMenu.hidden = !open;
        if (!open && restoreFocus) {
            menuButton.focus();
        }
    };

    menuButton.addEventListener('click', () => {
        setOpen(menuButton.getAttribute('aria-expanded') !== 'true');
    });
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && !mobileMenu.hidden) {
            setOpen(false, { restoreFocus: true });
        }
    });
    document.addEventListener('click', (event) => {
        if (!mobileMenu.hidden && !mobileMenu.contains(event.target) && !menuButton.contains(event.target)) {
            setOpen(false);
        }
    });
    window.matchMedia?.('(min-width: 75.0625rem)').addEventListener?.('change', (query) => {
        if (query.matches) setOpen(false);
    });
}

function selectTab(tabs, tab, { focus = false } = {}) {
    tabs.forEach((candidate) => {
        const selected = candidate === tab;
        candidate.setAttribute('aria-selected', String(selected));
        candidate.tabIndex = selected ? 0 : -1;
        const panel = document.getElementById(candidate.getAttribute('aria-controls'));
        if (panel) panel.hidden = !selected;
    });
    if (focus) tab.focus();
}

function initializeTabs() {
    document.querySelectorAll('[data-tabs]').forEach((container) => {
        const tabs = [...container.querySelectorAll('[role="tab"]')];
        if (!tabs.length) {
            return;
        }
        container.classList.add('is-enhanced');
        selectTab(tabs, tabs.find((tab) => tab.getAttribute('aria-selected') === 'true') || tabs[0]);
        tabs.forEach((tab, index) => {
            tab.addEventListener('click', () => selectTab(tabs, tab));
            tab.addEventListener('keydown', (event) => {
                const moves = { ArrowRight: index + 1, ArrowLeft: index - 1, Home: 0, End: tabs.length - 1 };
                if (!(event.key in moves)) return;
                event.preventDefault();
                selectTab(tabs, tabs[(moves[event.key] + tabs.length) % tabs.length], { focus: true });
            });
        });
    });
}

function initializeLocalNavigation() {
    const nav = document.querySelector('[data-local-nav]');
    if (!nav || !('IntersectionObserver' in window)) {
        return;
    }
    const links = new Map();
    nav.querySelectorAll('a[href^="#"]').forEach((link) => {
        const section = document.getElementById(link.getAttribute('href').slice(1));
        if (section) links.set(section, link);
    });
    const visible = new Set();
    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (entry.isIntersecting) visible.add(entry.target);
            else visible.delete(entry.target);
        });
        const current = [...links.keys()].find((section) => visible.has(section));
        links.forEach((link, section) => {
            if (section === current) link.setAttribute('aria-current', 'true');
            else link.removeAttribute('aria-current');
        });
    }, { rootMargin: '-20% 0px -60% 0px' });
    links.forEach((_link, section) => observer.observe(section));
}

function initializeRevealButtons() {
    document.querySelectorAll('[data-reveal-target]').forEach((button) => {
        const input = document.getElementById(button.getAttribute('data-reveal-target'));
        if (!input) return;
        button.addEventListener('click', () => {
            const reveal = input.type === 'password';
            input.type = reveal ? 'text' : 'password';
            button.setAttribute('aria-pressed', String(reveal));
            button.textContent = reveal ? 'Hide' : 'Show';
            input.focus();
        });
    });
}

function initializeSubmitOnce() {
    document.querySelectorAll('form[data-submit-once]').forEach((form) => {
        form.addEventListener('submit', () => {
            const submit = form.querySelector('button[type="submit"]');
            if (submit) {
                submit.setAttribute('aria-busy', 'true');
                window.setTimeout(() => { submit.disabled = true; });
            }
        });
    });
}

document.addEventListener('DOMContentLoaded', () => {
    initializeMobileNavigation();
    initializeCopyButtons();
    initializeTabs();
    initializeLocalNavigation();
    initializeSubmitOnce();
    initializeRevealButtons();
    registerServiceWorker();
});

window.MultiLLM = Object.freeze({
    copyText,
    showToast
});
