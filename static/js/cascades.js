(() => {
    'use strict';
    const panel = document.getElementById('cascade-panel');
    if (!panel) return;
    const select = document.getElementById('cascade-select');
    const editor = document.getElementById('cascade-config');
    const status = document.getElementById('cascade-status');
    const form = document.getElementById('cascade-form');
    let cascades = [];
    const example = {name: 'cascade:my-route', tiers: [{model: 'auto:glm-5.2'}, {model: 'auto:gpt-6.1'}], checks: ['complete', 'no_refusal']};
    const show = () => {
        const value = cascades.find(cascade => cascade.name === select.value) || example;
        const {updated_at, ...config} = value;
        editor.value = JSON.stringify(config, null, 2);
    };
    const load = async (method = 'GET', config) => {
        const headers = {'Accept': 'application/json'};
        if (config) {
            headers['Content-Type'] = 'application/json';
            const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
            if (csrf) headers['X-CSRFToken'] = csrf;
        }
        const response = await fetch(panel.dataset.endpoint, {method, headers, credentials: 'same-origin', ...(config ? {body: JSON.stringify(config)} : {})});
        const body = await response.json();
        if (!response.ok) throw new Error(body.error?.message || body.message || `HTTP ${response.status}`);
        cascades = body.cascades;
        const selected = config?.name || select.value;
        select.replaceChildren();
        const blank = document.createElement('option');
        blank.value = ''; blank.textContent = 'New cascade'; select.appendChild(blank);
        for (const cascade of cascades) {
            const option = document.createElement('option');
            option.value = cascade.name; option.textContent = cascade.name; select.appendChild(option);
        }
        select.value = selected;
        show();
    };
    select.addEventListener('change', show);
    form.addEventListener('submit', async event => {
        event.preventDefault();
        const button = form.querySelector('button');
        button.disabled = true;
        try {
            const config = JSON.parse(editor.value);
            if (!config || typeof config.name !== 'string' || !Array.isArray(config.tiers) || config.tiers.length < 2 || config.tiers.length > 4 || !Array.isArray(config.checks)) {
                throw new Error('Enter a cascade name, 2–4 tiers and an array of checks.');
            }
            await load('PUT', config);
            status.textContent = 'Cascade saved.';
        } catch (error) { status.textContent = error.message; }
        finally { button.disabled = false; }
    });
    show();
    load().catch(error => { status.textContent = error.message; });
})();
