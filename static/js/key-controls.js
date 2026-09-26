(function initializeKeyControls() {
    const lines = (value) => String(value || '').split(/[\s,]+/).map((item) => item.trim()).filter(Boolean);
    const amount = (value) => (String(value).trim() === '' ? null : Number(value));

    /** The PUT /users/<name>/controls body for the dialog's field values. */
    function controlsPayload(fields) {
        return {
            daily_budget_usd: amount(fields.daily_budget_usd),
            monthly_budget_usd: amount(fields.monthly_budget_usd),
            allowed_models: lines(fields.allowed_models),
            allowed_ips: lines(fields.allowed_ips),
            // datetime-local has no zone; the dialog labels it UTC.
            expires_at: fields.expires_at ? `${fields.expires_at}${fields.expires_at.length === 16 ? ':00' : ''}Z` : null,
        };
    }

    window.MultiLLMKeyControls = Object.freeze({ controlsPayload });

    const dialog = typeof document !== 'undefined' ? document.getElementById('key-controls-dialog') : null;
    const form = typeof document !== 'undefined' ? document.getElementById('key-controls-form') : null;
    if (!dialog || !form) {
        return;
    }
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
    let username = '';

    function field(name) {
        return form.elements.namedItem(name);
    }

    document.addEventListener('click', (event) => {
        const button = event.target.closest('[data-controls-user]');
        if (!button) {
            return;
        }
        username = button.dataset.controlsUser;
        let controls = {};
        try {
            controls = JSON.parse(button.dataset.controls || '{}') || {};
        } catch (error) {
            controls = {};
        }
        document.getElementById('key-controls-user').textContent = username;
        field('daily_budget_usd').value = controls.daily_budget_usd ?? '';
        field('monthly_budget_usd').value = controls.monthly_budget_usd ?? '';
        field('allowed_models').value = (controls.allowed_models || []).join('\n');
        field('allowed_ips').value = (controls.allowed_ips || []).join('\n');
        field('expires_at').value = controls.expires_at ? String(controls.expires_at).slice(0, 16) : '';
        if (typeof dialog.showModal === 'function') {
            dialog.showModal();
        } else {
            dialog.setAttribute('open', '');
        }
    });

    function close() {
        if (typeof dialog.close === 'function') {
            dialog.close();
        } else {
            dialog.removeAttribute('open');
        }
    }

    document.getElementById('key-controls-cancel')?.addEventListener('click', close);

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const submit = form.querySelector('button[type="submit"]');
        submit.disabled = true;
        submit.setAttribute('aria-busy', 'true');
        try {
            const values = Object.fromEntries(new FormData(form).entries());
            const response = await fetch(`/users/${encodeURIComponent(username)}/controls`, {
                method: 'PUT',
                credentials: 'same-origin',
                headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                body: JSON.stringify(controlsPayload(values)),
            });
            const payload = await response.json().catch(() => ({}));
            if (!response.ok) {
                throw new Error(payload.message || payload.error || `HTTP ${response.status}`);
            }
            close();
            window.location.reload();
        } catch (error) {
            window.MultiLLM?.showToast(error.message, 'error');
        } finally {
            submit.disabled = false;
            submit.removeAttribute('aria-busy');
        }
    });
}());
