(function initializeProxyDocumentation() {
    const stateNode = document.getElementById('proxy-documentation-state');
    const tableBody = document.getElementById('model-table-body');
    if (!stateNode || !tableBody) {
        return;
    }

    const searchInput = document.getElementById('model-search');
    const providerSelect = document.getElementById('model-provider');
    const capabilitySelect = document.getElementById('model-capability');
    const sourceSelect = document.getElementById('model-source');
    const resultSummary = document.getElementById('model-result-summary');
    const emptyState = document.getElementById('model-empty');
    const previousButton = document.getElementById('model-previous');
    const nextButton = document.getElementById('model-next');
    const pageLabel = document.getElementById('model-page-label');
    const pageSize = 50;
    let currentPage = 1;
    let models = [];

    function normalized(value) {
        return String(value || '').trim().toLowerCase();
    }

    function parseState() {
        try {
            const state = JSON.parse(stateNode.textContent || '{}');
            models = Array.isArray(state.models) ? state.models : [];
        } catch (error) {
            console.error('Could not parse proxy documentation state:', error);
            models = [];
            resultSummary.textContent = 'The live model catalog could not be loaded.';
        }
    }

    function populateProviderFilter() {
        const providers = [...new Set(models.map((model) => model.provider))].sort();
        for (const provider of providers) {
            const option = document.createElement('option');
            option.value = provider;
            option.textContent = provider;
            providerSelect.appendChild(option);
        }
    }

    function capabilityLabels(model) {
        const capabilities = model.capabilities || {};
        const labels = [];
        if (capabilities.supports_chat !== false) {
            labels.push('chat');
        }
        if (capabilities.supports_images) {
            labels.push('images');
        }
        if (capabilities.supports_vision) {
            labels.push('vision');
        }
        if (capabilities.supports_tools) {
            labels.push('tools');
        }
        return labels;
    }

    function matchesFilters(model) {
        const query = normalized(searchInput.value);
        const provider = providerSelect.value;
        const capability = capabilitySelect.value;
        const source = sourceSelect.value;
        const sources = Array.isArray(model.sources) ? model.sources : [];
        const capabilities = capabilityLabels(model);

        if (query && !normalized(`${model.id} ${model.provider} ${model.model}`).includes(query)) {
            return false;
        }
        if (provider && model.provider !== provider) {
            return false;
        }
        if (capability && !capabilities.includes(capability)) {
            return false;
        }
        return !source || sources.includes(source);
    }

    function textCell(value, className = '') {
        const cell = document.createElement('td');
        cell.textContent = value;
        if (className) {
            cell.className = className;
        }
        return cell;
    }

    function modelCell(model) {
        const cell = document.createElement('th');
        cell.scope = 'row';
        const code = document.createElement('code');
        code.textContent = model.id;
        cell.appendChild(code);
        return cell;
    }

    function capabilitiesCell(model) {
        const cell = document.createElement('td');
        const wrapper = document.createElement('div');
        wrapper.className = 'table-tags';
        const labels = capabilityLabels(model);
        for (const label of labels.length ? labels : ['provider native']) {
            const tag = document.createElement('span');
            tag.textContent = label;
            wrapper.appendChild(tag);
        }
        cell.appendChild(wrapper);
        return cell;
    }

    function copyCell(model) {
        const cell = document.createElement('td');
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'model-copy-button';
        button.setAttribute('data-copy-value', model.id);
        button.setAttribute('aria-label', `Copy ${model.id}`);
        button.textContent = 'Copy';
        cell.appendChild(button);
        return cell;
    }

    function renderRow(model) {
        const row = document.createElement('tr');
        if (!model.configured || model.status === 'disabled') {
            row.className = 'model-row--inactive';
        }
        row.append(
            modelCell(model),
            textCell(model.provider),
            capabilitiesCell(model),
            textCell((model.sources || []).join(', ')),
            textCell(
                model.status === 'disabled'
                    ? 'disabled'
                    : model.configured
                        ? model.status
                        : `${model.status} · key missing`,
            ),
            copyCell(model),
        );
        return row;
    }

    function renderModels() {
        const filtered = models.filter(matchesFilters);
        const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
        currentPage = Math.min(currentPage, totalPages);
        const firstIndex = (currentPage - 1) * pageSize;
        const visibleModels = filtered.slice(firstIndex, firstIndex + pageSize);

        tableBody.replaceChildren(...visibleModels.map(renderRow));
        emptyState.hidden = filtered.length !== 0;
        resultSummary.textContent = `${filtered.length} of ${models.length} models`;
        pageLabel.textContent = `Page ${currentPage} of ${totalPages}`;
        previousButton.disabled = currentPage === 1;
        nextButton.disabled = currentPage === totalPages;
    }

    function resetAndRender() {
        currentPage = 1;
        renderModels();
    }

    for (const control of [searchInput, providerSelect, capabilitySelect, sourceSelect]) {
        control.addEventListener(control === searchInput ? 'input' : 'change', resetAndRender);
    }
    previousButton.addEventListener('click', () => {
        currentPage = Math.max(1, currentPage - 1);
        renderModels();
    });
    nextButton.addEventListener('click', () => {
        currentPage += 1;
        renderModels();
    });

    parseState();
    populateProviderFilter();
    renderModels();
}());
