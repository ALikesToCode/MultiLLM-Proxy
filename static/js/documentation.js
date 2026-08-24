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
        const providerMetadata = model.provider_metadata || {};
        const endpoint = normalized(providerMetadata.endpoint);
        const outputModalities = Array.isArray(providerMetadata.output_modalities)
            ? providerMetadata.output_modalities.map(normalized)
            : [];
        const labels = [];
        if (endpoint.includes('/chat/completions') || (!endpoint && capabilities.supports_chat !== false)) {
            labels.push('chat');
        }
        if (
            providerMetadata.supports_image_output === true
            || outputModalities.includes('image')
            || (!endpoint && capabilities.supports_images)
        ) {
            labels.push('images');
        }
        if (outputModalities.includes('video')) {
            labels.push('video');
        }
        if (providerMetadata.supports_vision === true || (!endpoint && capabilities.supports_vision)) {
            labels.push('vision');
        }
        if (providerMetadata.supports_tools === true || (!endpoint && capabilities.supports_tools)) {
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

        const providerMetadata = model.provider_metadata || {};
        const inputModalities = Array.isArray(providerMetadata.input_modalities)
            ? providerMetadata.input_modalities
            : [];
        const outputModalities = Array.isArray(providerMetadata.output_modalities)
            ? providerMetadata.output_modalities
            : [];
        const searchable = [
            model.id,
            model.provider,
            model.model,
            providerMetadata.owned_by,
            providerMetadata.endpoint,
            providerMetadata.modality,
            providerMetadata.description,
            providerMetadata.metadata_resolved_from,
            ...inputModalities,
            ...outputModalities,
        ].join(' ');
        if (query && !normalized(searchable).includes(query)) {
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

    function limitsCell(model) {
        const limits = [];
        for (const [value, label] of [
            [model.context_window, 'context'],
            [model.max_output_tokens, 'output'],
        ]) {
            const parsed = Number(value);
            if (Number.isSafeInteger(parsed) && parsed > 0) {
                limits.push(`${parsed.toLocaleString()} ${label}`);
            }
        }
        return textCell(limits.length ? limits.join(' · ') : 'Not reported');
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

    function providerDetailsCell(model) {
        const cell = document.createElement('td');
        const providerMetadata = model.provider_metadata || {};
        const details = [];
        const inputModalities = Array.isArray(providerMetadata.input_modalities)
            ? providerMetadata.input_modalities.join('+')
            : '';
        const outputModalities = Array.isArray(providerMetadata.output_modalities)
            ? providerMetadata.output_modalities.join('+')
            : '';
        if (providerMetadata.endpoint) {
            details.push(providerMetadata.endpoint);
        }
        if (inputModalities || outputModalities) {
            details.push(`${inputModalities || '?'} → ${outputModalities || '?'}`);
        }
        if (providerMetadata.required_plan) {
            details.push(`plan: ${providerMetadata.required_plan}`);
        } else if (providerMetadata.premium === true) {
            details.push('premium');
        }
        if (
            providerMetadata.token_multiplier !== null
            && providerMetadata.token_multiplier !== undefined
            && Number.isFinite(Number(providerMetadata.token_multiplier))
        ) {
            details.push(`${Number(providerMetadata.token_multiplier).toLocaleString()}× tokens`);
        }
        if (providerMetadata.owned_by) {
            details.push(`by ${providerMetadata.owned_by}`);
        }
        if (providerMetadata.metadata_resolved_from) {
            details.push(`metadata: ${providerMetadata.metadata_resolved_from}`);
        }

        const wrapper = document.createElement('div');
        wrapper.className = 'provider-detail-list';
        for (const detail of details.length ? details : ['Not reported']) {
            const line = document.createElement('span');
            line.textContent = detail;
            wrapper.appendChild(line);
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
            providerDetailsCell(model),
            limitsCell(model),
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
