(() => {
    'use strict';
    const panel = document.getElementById('safety-panel');
    if (!panel) return;
    const form = document.getElementById('safety-form');
    const controls = document.getElementById('safety-controls');
    const enabled = document.getElementById('safety-enabled');
    const failure = document.getElementById('safety-failure-mode');
    const status = document.getElementById('safety-status');
    const reload = document.getElementById('safety-reload');
    let revision = null;

    async function call(settings) {
        const headers = {'Accept': 'application/json'};
        if (settings) {
            headers['Content-Type'] = 'application/json';
            const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
            if (csrf) headers['X-CSRFToken'] = csrf;
        }
        const response = await fetch(panel.dataset.endpoint, {method: settings ? 'POST' : 'GET', headers,
            credentials: 'same-origin', ...(settings ? {body: JSON.stringify(settings)} : {})});
        const body = await response.json();
        if (!response.ok) {
            const error = new Error(response.status === 409
                ? 'Settings changed in another session. Reload the saved settings before editing again.'
                : `Could not ${settings ? 'save' : 'load'} screening settings (HTTP ${response.status}).`);
            error.conflict = response.status === 409;
            throw error;
        }
        const value = body.settings;
        if (!value || typeof value.enabled !== 'boolean' || !['allow', 'block'].includes(value.failure_mode)
            || !Number.isSafeInteger(value.revision) || value.revision < 0) throw new Error('Invalid screening settings response.');
        return value;
    }

    function display(value) {
        enabled.checked = value.enabled;
        failure.value = value.failure_mode;
        revision = value.revision;
        status.textContent = value.enabled ? 'Text screening is enabled.' : 'Text screening is off.';
        controls.disabled = false;
        reload.hidden = true;
    }

    async function load() {
        controls.disabled = true;
        reload.disabled = true;
        status.textContent = 'Loading screening settings…';
        try { display(await call()); }
        catch (error) { status.textContent = error.message; reload.hidden = false; }
        finally { reload.disabled = false; }
    }

    form.addEventListener('submit', async event => {
        event.preventDefault();
        if (controls.disabled || revision === null) return;
        controls.disabled = true;
        const settings = {enabled: enabled.checked, failure_mode: failure.value, revision};
        try { display(await call(settings)); }
        catch (error) {
            status.textContent = error.message;
            // A save may have committed before a lost reply. Reload before any retry.
            revision = null;
            reload.hidden = false;
        }
    });
    reload.addEventListener('click', load);
    load();
})();
