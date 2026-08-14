(function initializeAutoRouteEditor() {
    const root = document.getElementById('operations-dashboard');
    const panel = document.getElementById('auto-route-panel');
    if (!root || !panel || root.dataset.admin !== 'true') {
        return;
    }

    const elements = {
        routeSelect: document.getElementById('auto-route-select'),
        routeName: document.getElementById('auto-route-name'),
        provider: document.getElementById('auto-route-provider'),
        model: document.getElementById('auto-route-model'),
        modelOptions: document.getElementById('auto-route-model-options'),
        candidates: document.getElementById('auto-route-candidates'),
        empty: document.getElementById('auto-route-empty'),
        count: document.getElementById('auto-route-count'),
        status: document.getElementById('auto-route-status'),
        newRoute: document.getElementById('new-auto-route'),
        addCandidate: document.getElementById('add-auto-route-candidate'),
        save: document.getElementById('save-auto-route')
    };
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
    const state = {
        routes: [],
        providers: [],
        activeRouteId: null,
        candidates: [],
        creating: false
    };

    function setStatus(message, tone) {
        elements.status.textContent = message;
        elements.status.classList.toggle('tone-danger-text', tone === 'error');
        elements.status.classList.toggle('tone-positive-text', tone === 'success');
    }

    function providerDetails(providerId) {
        return state.providers.find((provider) => provider.id === providerId) || {
            id: providerId,
            configured: false,
            models: []
        };
    }

    function splitModelId(modelId) {
        const separator = modelId.indexOf(':');
        return {
            provider: modelId.slice(0, separator),
            model: modelId.slice(separator + 1)
        };
    }

    function candidateFromId(modelId) {
        const parsed = splitModelId(modelId);
        const provider = providerDetails(parsed.provider);
        return {
            model_id: modelId,
            provider: parsed.provider,
            model: parsed.model,
            configured: provider.configured,
            status: 'available'
        };
    }

    function renderRouteSelect() {
        elements.routeSelect.replaceChildren();
        if (state.creating) {
            const draft = document.createElement('option');
            draft.value = '__new__';
            draft.textContent = 'New unsaved route';
            elements.routeSelect.appendChild(draft);
        }
        state.routes.forEach((route) => {
            const option = document.createElement('option');
            option.value = route.id;
            option.textContent = route.id;
            elements.routeSelect.appendChild(option);
        });
        elements.routeSelect.value = state.creating
            ? '__new__'
            : state.activeRouteId || '';
    }

    function createCandidateButton(label, action, index, disabled) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'auto-route-candidate__button';
        button.textContent = label;
        button.dataset.action = action;
        button.dataset.index = String(index);
        button.disabled = disabled;
        return button;
    }

    function renderCandidates() {
        elements.candidates.replaceChildren();
        state.candidates.forEach((candidate, index) => {
            const item = document.createElement('li');
            const priority = document.createElement('span');
            const identity = document.createElement('span');
            const model = document.createElement('strong');
            const metadata = document.createElement('small');
            const controls = document.createElement('span');
            const configured = candidate.configured ? 'configured' : 'not configured';
            const status = candidate.status || 'available';

            item.className = 'auto-route-candidate';
            priority.className = 'auto-route-candidate__priority';
            priority.textContent = String(index + 1);
            identity.className = 'auto-route-candidate__identity';
            model.textContent = candidate.model_id;
            metadata.textContent = `${configured} · ${status}`;
            metadata.className = candidate.configured
                ? 'tone-positive-text'
                : 'tone-warning-text';
            identity.append(model, metadata);
            controls.className = 'auto-route-candidate__controls';
            controls.append(
                createCandidateButton('Up', 'up', index, index === 0),
                createCandidateButton(
                    'Down',
                    'down',
                    index,
                    index === state.candidates.length - 1,
                ),
                createCandidateButton('Remove', 'remove', index, false)
            );
            item.append(priority, identity, controls);
            elements.candidates.appendChild(item);
        });
        elements.empty.hidden = state.candidates.length > 0;
        elements.count.textContent = `${state.candidates.length} ${
            state.candidates.length === 1 ? 'candidate' : 'candidates'
        }`;
    }

    function loadRoute(routeId) {
        const route = state.routes.find((item) => item.id === routeId);
        if (!route) {
            return;
        }
        state.creating = false;
        state.activeRouteId = route.id;
        state.candidates = route.candidates.map((candidate) => ({ ...candidate }));
        elements.routeName.value = route.id.slice('auto:'.length);
        elements.routeName.disabled = true;
        renderRouteSelect();
        renderCandidates();
        setStatus(`Loaded ${route.id}. Changes are local until saved.`);
    }

    function startNewRoute() {
        state.creating = true;
        state.activeRouteId = null;
        state.candidates = [];
        elements.routeName.disabled = false;
        elements.routeName.value = '';
        renderRouteSelect();
        renderCandidates();
        setStatus('Enter a model name, add candidates, then save.');
        elements.routeName.focus();
    }

    function populateProviders() {
        elements.provider.replaceChildren();
        state.providers.forEach((provider) => {
            const option = document.createElement('option');
            option.value = provider.id;
            option.textContent = provider.configured
                ? provider.id
                : `${provider.id} · not configured`;
            elements.provider.appendChild(option);
        });
        const preferred = state.providers.find((provider) => provider.id === 'nanogpt');
        if (preferred) {
            elements.provider.value = preferred.id;
        }
        populateModelOptions();
    }

    function populateModelOptions() {
        elements.modelOptions.replaceChildren();
        providerDetails(elements.provider.value).models.forEach((modelId) => {
            const option = document.createElement('option');
            option.value = modelId;
            elements.modelOptions.appendChild(option);
        });
    }

    function moveCandidate(index, offset) {
        const target = index + offset;
        if (target < 0 || target >= state.candidates.length) {
            return;
        }
        const [candidate] = state.candidates.splice(index, 1);
        state.candidates.splice(target, 0, candidate);
        renderCandidates();
        setStatus('Priority order changed locally. Save to apply it.');
    }

    function addCandidate() {
        const providerId = elements.provider.value;
        const model = elements.model.value.trim();
        if (!providerId || !model) {
            setStatus('Choose a provider and enter its exact model ID.', 'error');
            elements.model.focus();
            return;
        }
        const modelId = `${providerId}:${model}`;
        if (state.candidates.some((candidate) => candidate.model_id === modelId)) {
            setStatus(`${modelId} is already in this route.`, 'error');
            return;
        }
        state.candidates.push(candidateFromId(modelId));
        elements.model.value = '';
        renderCandidates();
        setStatus(`${modelId} added locally. Save to apply it.`);
        elements.model.focus();
    }

    async function responseMessage(response) {
        try {
            const payload = await response.json();
            if (typeof payload.message === 'string') {
                return payload.message;
            }
            if (typeof payload.error === 'string') {
                return payload.error;
            }
            if (typeof payload.error?.message === 'string') {
                return payload.error.message;
            }
            return `HTTP ${response.status}`;
        } catch (error) {
            return `HTTP ${response.status}`;
        }
    }

    async function saveRoute() {
        const routeName = elements.routeName.value.trim();
        if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(routeName)) {
            setStatus('Use letters, numbers, dots, underscores, or hyphens.', 'error');
            elements.routeName.focus();
            return;
        }
        if (!state.candidates.length) {
            setStatus('Add at least one provider candidate before saving.', 'error');
            return;
        }

        const routeId = `auto:${routeName}`;
        elements.save.disabled = true;
        setStatus(`Saving ${routeId}…`);
        try {
            const headers = new Headers({
                Accept: 'application/json',
                'Content-Type': 'application/json'
            });
            if (csrfToken) {
                headers.set('X-CSRFToken', csrfToken);
            }
            const response = await fetch(root.dataset.autoRoutes, {
                method: 'PUT',
                credentials: 'same-origin',
                headers,
                body: JSON.stringify({
                    route_id: routeId,
                    candidates: state.candidates.map((candidate) => candidate.model_id)
                })
            });
            if (!response.ok) {
                throw new Error(await responseMessage(response));
            }
            const payload = await response.json();
            state.routes = payload.routes || [];
            state.providers = payload.providers || [];
            populateProviders();
            loadRoute(routeId);
            setStatus(`${routeId} is active for new chat requests.`, 'success');
            window.MultiLLM?.showToast(`${routeId} priority saved`, 'success');
        } catch (error) {
            console.error('Auto route save failed:', error);
            setStatus(`Save failed: ${error.message}`, 'error');
            window.MultiLLM?.showToast('Auto route could not be saved', 'error');
        } finally {
            elements.save.disabled = false;
        }
    }

    async function loadRoutes() {
        setStatus('Loading priorities…');
        try {
            const response = await fetch(root.dataset.autoRoutes, {
                credentials: 'same-origin',
                headers: { Accept: 'application/json' }
            });
            if (!response.ok) {
                throw new Error(await responseMessage(response));
            }
            const payload = await response.json();
            state.routes = payload.routes || [];
            state.providers = payload.providers || [];
            populateProviders();
            if (state.routes.length) {
                loadRoute(state.routes[0].id);
            } else {
                startNewRoute();
            }
        } catch (error) {
            console.error('Auto route load failed:', error);
            setStatus(`Priorities unavailable: ${error.message}`, 'error');
            elements.save.disabled = true;
            elements.addCandidate.disabled = true;
        }
    }

    elements.routeSelect.addEventListener('change', (event) => {
        if (event.target.value === '__new__') {
            return;
        }
        loadRoute(event.target.value);
    });
    elements.provider.addEventListener('change', populateModelOptions);
    elements.newRoute.addEventListener('click', startNewRoute);
    elements.addCandidate.addEventListener('click', addCandidate);
    elements.model.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            event.preventDefault();
            addCandidate();
        }
    });
    elements.candidates.addEventListener('click', (event) => {
        const button = event.target.closest('button[data-action]');
        if (!button) {
            return;
        }
        const index = Number(button.dataset.index);
        if (button.dataset.action === 'up') {
            moveCandidate(index, -1);
        } else if (button.dataset.action === 'down') {
            moveCandidate(index, 1);
        } else if (button.dataset.action === 'remove') {
            state.candidates.splice(index, 1);
            renderCandidates();
            setStatus('Candidate removed locally. Save to apply it.');
        }
    });
    elements.save.addEventListener('click', saveRoute);

    loadRoutes();
}());
