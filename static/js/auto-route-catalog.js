(function registerAutoRouteCatalogView() {
    const MAX_VISIBLE_MODELS = 200;

    function formatLimit(value, label) {
        const parsed = Number(value);
        if (!Number.isSafeInteger(parsed) || parsed <= 0) {
            return '';
        }
        return `${parsed.toLocaleString()} ${label}`;
    }

    function createAutoRouteCatalog({
        getState,
        onAddModel,
        onRefresh
    }) {
        const elements = {
            providerCount: document.getElementById('auto-route-provider-count'),
            providerList: document.getElementById('auto-route-provider-list'),
            count: document.getElementById('auto-route-catalog-count'),
            search: document.getElementById('auto-route-catalog-search'),
            provider: document.getElementById('auto-route-catalog-provider'),
            refresh: document.getElementById('refresh-auto-route-catalog'),
            status: document.getElementById('auto-route-catalog-status'),
            list: document.getElementById('auto-route-model-catalog'),
            empty: document.getElementById('auto-route-catalog-empty')
        };

        function populateProviderFilter() {
            const { providers } = getState();
            const selectedProvider = elements.provider.value;
            elements.provider.replaceChildren();
            const allProviders = document.createElement('option');
            allProviders.value = '';
            allProviders.textContent = 'All providers';
            elements.provider.appendChild(allProviders);
            providers.forEach((provider) => {
                const option = document.createElement('option');
                option.value = provider.id;
                option.textContent = `${provider.id} (${provider.models.length})`;
                elements.provider.appendChild(option);
            });
            if (providers.some((provider) => provider.id === selectedProvider)) {
                elements.provider.value = selectedProvider;
            }
        }

        function renderProviderConfiguration() {
            const { providers } = getState();
            elements.providerList.replaceChildren();
            const configuredCount = providers.filter(
                (provider) => provider.configured
            ).length;
            elements.providerCount.textContent = `${configuredCount}/${providers.length} configured`;

            providers.forEach((provider) => {
                const item = document.createElement('li');
                const heading = document.createElement('div');
                const name = document.createElement('strong');
                const configurationState = document.createElement('span');
                const credential = document.createElement('code');
                const catalog = document.createElement('small');
                const modelWord = provider.models.length === 1 ? 'model' : 'models';

                item.className = 'auto-route-provider-item';
                heading.className = 'auto-route-provider-item__heading';
                name.textContent = provider.id;
                configurationState.className = `auto-route-configuration-state ${
                    provider.configured
                        ? 'auto-route-configuration-state--ready'
                        : 'auto-route-configuration-state--missing'
                }`;
                configurationState.textContent = provider.configured
                    ? 'configured'
                    : 'key missing';
                heading.append(name, configurationState);
                credential.textContent = (provider.credential_env || []).join(' · ');
                if (provider.catalog_path) {
                    const refreshed = provider.catalog_updated_at
                        ? ` · refreshed ${new Date(provider.catalog_updated_at).toLocaleString()}`
                        : '';
                    catalog.textContent = `${provider.models.length} ${modelWord} · live catalog ${provider.catalog_path}${refreshed}`;
                } else {
                    catalog.textContent = `${provider.models.length} ${modelWord} · built-in catalog only`;
                }
                item.append(heading, credential, catalog);
                elements.providerList.appendChild(item);
            });
        }

        function renderModels() {
            const { candidates, modelCatalog } = getState();
            const query = elements.search.value.trim().toLowerCase();
            const providerFilter = elements.provider.value;
            const filteredModels = modelCatalog.filter((model) => {
                if (providerFilter && model.provider !== providerFilter) {
                    return false;
                }
                return !query || model.id.toLowerCase().includes(query);
            });

            elements.list.replaceChildren();
            const visibleModels = filteredModels.slice(0, MAX_VISIBLE_MODELS);
            visibleModels.forEach((model) => {
                const item = document.createElement('li');
                const identity = document.createElement('span');
                const modelId = document.createElement('strong');
                const metadata = document.createElement('small');
                const addButton = document.createElement('button');
                const isAdded = candidates.some(
                    (candidate) => candidate.model_id === model.id
                );
                const isDisabled = model.status === 'disabled';
                const limits = [
                    formatLimit(model.context_window, 'context'),
                    formatLimit(model.max_output_tokens, 'output'),
                ].filter(Boolean);

                item.className = 'auto-route-model-item';
                identity.className = 'auto-route-model-item__identity';
                modelId.textContent = model.id;
                metadata.textContent = [
                    model.configured ? 'configured' : 'key missing',
                    (model.sources || []).join(' + ') || 'catalog',
                    ...limits,
                ].join(' · ');
                identity.append(modelId, metadata);
                addButton.type = 'button';
                addButton.className = 'button button--secondary';
                addButton.dataset.modelId = model.id;
                addButton.disabled = isAdded || isDisabled;
                addButton.textContent = isDisabled
                    ? 'Disabled'
                    : isAdded
                        ? 'Added'
                        : 'Add';
                item.append(identity, addButton);
                elements.list.appendChild(item);
            });

            elements.empty.hidden = filteredModels.length > 0;
            elements.count.textContent = filteredModels.length > MAX_VISIBLE_MODELS
                ? `${visibleModels.length} shown · ${filteredModels.length} matching · ${modelCatalog.length} total`
                : `${filteredModels.length}/${modelCatalog.length} models`;
        }

        function render() {
            populateProviderFilter();
            renderProviderConfiguration();
            renderModels();
        }

        function setStatus(message) {
            elements.status.textContent = message;
        }

        function setRefreshing(refreshing) {
            elements.refresh.disabled = refreshing;
            if (refreshing) {
                setStatus('Refreshing configured provider catalogs…');
            }
        }

        elements.search.addEventListener('input', renderModels);
        elements.provider.addEventListener('change', renderModels);
        elements.refresh.addEventListener('click', onRefresh);
        elements.list.addEventListener('click', (event) => {
            const button = event.target.closest('button[data-model-id]');
            if (button) {
                onAddModel(button.dataset.modelId);
            }
        });

        return { render, renderModels, setRefreshing, setStatus };
    }

    window.MultiLLMAutoRoutes = Object.freeze({ createAutoRouteCatalog });
}());
