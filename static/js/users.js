(function initializeAccessConsole() {
    const root = document.getElementById('access-console');
    if (!root) {
        return;
    }

    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
    const secretDialog = document.getElementById('secret-dialog');
    const secretValue = document.getElementById('secret-value');

    function showSecret(apiKey) {
        if (!secretDialog || !secretValue) {
            return;
        }
        secretValue.textContent = apiKey;
        if (typeof secretDialog.showModal === 'function') {
            secretDialog.showModal();
        } else {
            secretDialog.setAttribute('open', '');
        }
    }

    function closeSecret() {
        if (!secretDialog) {
            return;
        }
        if (typeof secretDialog.close === 'function') {
            secretDialog.close();
        } else {
            secretDialog.removeAttribute('open');
        }
    }

    async function fetchJson(url, options) {
        const headers = new Headers(options.headers || {});
        headers.set('Accept', 'application/json');
        headers.set('X-CSRFToken', csrfToken);
        const response = await fetch(url, {
            ...options,
            credentials: 'same-origin',
            headers
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(payload.message || payload.error || `HTTP ${response.status}`);
        }
        return payload;
    }

    function filterAccounts() {
        const search = document.getElementById('search-users')?.value.trim().toLowerCase() || '';
        const role = document.getElementById('filter-users')?.value || 'all';
        const rows = [...document.querySelectorAll('[data-user-row]')];
        let visible = 0;
        rows.forEach((row) => {
            const matchesSearch = !search || row.dataset.username.toLowerCase().includes(search);
            const matchesRole = role === 'all' || row.dataset.role === role;
            row.hidden = !(matchesSearch && matchesRole);
            if (!row.hidden) {
                visible += 1;
            }
        });
        const empty = document.getElementById('users-empty');
        if (empty) {
            empty.hidden = visible > 0;
        }
    }

    document.getElementById('create-user-form')?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const form = event.currentTarget;
        const formData = new FormData(form);
        const submit = form.querySelector('button[type="submit"]');
        submit.disabled = true;
        try {
            const payload = await fetchJson('/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: String(formData.get('username') || '').trim(),
                    is_admin: formData.get('is_admin') === 'on'
                })
            });
            showSecret(payload.user.api_key);
            form.reset();
            secretDialog?.addEventListener('close', () => window.location.reload(), { once: true });
        } catch (error) {
            window.MultiLLM?.showToast(error.message, 'error');
        } finally {
            submit.disabled = false;
        }
    });

    root.addEventListener('click', async (event) => {
        const rotateButton = event.target.closest('[data-rotate-user]');
        const deleteButton = event.target.closest('[data-delete-user]');
        if (!rotateButton && !deleteButton) {
            return;
        }

        const username = (rotateButton || deleteButton).dataset.rotateUser
            || (rotateButton || deleteButton).dataset.deleteUser;

        if (rotateButton) {
            if (!window.confirm(`Rotate ${username}'s key? The current key will stop working immediately.`)) {
                return;
            }
            rotateButton.disabled = true;
            try {
                const payload = await fetchJson(`/users/${encodeURIComponent(username)}/rotate-key`, {
                    method: 'POST'
                });
                showSecret(payload.api_key);
            } catch (error) {
                window.MultiLLM?.showToast(error.message, 'error');
            } finally {
                rotateButton.disabled = false;
            }
            return;
        }

        if (!window.confirm(`Delete ${username}? This account and its API key will stop working.`)) {
            return;
        }
        deleteButton.disabled = true;
        try {
            await fetchJson(`/users/${encodeURIComponent(username)}`, { method: 'DELETE' });
            window.location.reload();
        } catch (error) {
            window.MultiLLM?.showToast(error.message, 'error');
            deleteButton.disabled = false;
        }
    });

    document.getElementById('search-users')?.addEventListener('input', filterAccounts);
    document.getElementById('filter-users')?.addEventListener('change', filterAccounts);
    document.getElementById('copy-secret')?.addEventListener('click', async () => {
        try {
            await window.MultiLLM.copyText(secretValue?.textContent || '');
            window.MultiLLM.showToast('API key copied');
        } catch (error) {
            window.MultiLLM?.showToast('Could not copy API key', 'error');
        }
    });
    document.getElementById('close-secret')?.addEventListener('click', closeSecret);
}());
