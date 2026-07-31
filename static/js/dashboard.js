(function initializeOperationsDashboard() {
    const root = document.getElementById('operations-dashboard');
    const initialStateNode = document.getElementById('dashboard-initial-state');
    if (!root || !initialStateNode) {
        return;
    }

    let initialState = {};
    try {
        initialState = JSON.parse(initialStateNode.textContent || '{}');
    } catch (error) {
        console.error('Dashboard state could not be parsed:', error);
    }

    const state = {
        system: initialState.system || {},
        stats: initialState.stats || {},
        analytics: initialState.analytics || {},
        providers: initialState.providers || {},
        recentActivity: initialState.recentActivity || [],
        requests: []
    };

    const isAdmin = root.dataset.admin === 'true';
    const metricNodes = new Map();
    document.querySelectorAll('[data-metric]').forEach((node) => {
        metricNodes.set(node.dataset.metric, node);
    });

    function setMetric(name, value) {
        const node = metricNodes.get(name);
        if (node) {
            node.textContent = value;
        }
    }

    function formatNumber(value) {
        return new Intl.NumberFormat().format(Number(value || 0));
    }

    function formatPercent(value) {
        return `${Number(value || 0).toFixed(1)}%`;
    }

    function formatLatency(value) {
        const numeric = Number(value || 0);
        return numeric >= 1000
            ? `${(numeric / 1000).toFixed(2)}s`
            : `${Math.round(numeric)}ms`;
    }

    function formatCost(value, precision = 4) {
        const numeric = Number(value || 0);
        return `$${numeric.toFixed(precision)}`;
    }

    function safeStateClass(value) {
        const normalized = String(value || 'closed').toLowerCase();
        return ['closed', 'degraded', 'open', 'half_open'].includes(normalized)
            ? `state-${normalized}`
            : 'tone-neutral';
    }

    function parseTimestamp(value) {
        if (!value) {
            return null;
        }
        const normalized = String(value).includes('T')
            ? String(value)
            : String(value).replace(' ', 'T');
        const parsed = new Date(normalized);
        return Number.isNaN(parsed.getTime()) ? null : parsed;
    }

    function relativeTime(value) {
        const parsed = parseTimestamp(value);
        if (!parsed) {
            return 'never';
        }
        const seconds = Math.max(0, Math.round((Date.now() - parsed.getTime()) / 1000));
        if (seconds < 60) {
            return `${seconds}s ago`;
        }
        if (seconds < 3600) {
            return `${Math.floor(seconds / 60)}m ago`;
        }
        if (seconds < 86400) {
            return `${Math.floor(seconds / 3600)}h ago`;
        }
        return `${Math.floor(seconds / 86400)}d ago`;
    }

    function createTextCell(value, className) {
        const cell = document.createElement('td');
        if (className) {
            cell.className = className;
        }
        cell.textContent = value ?? '—';
        return cell;
    }

    function createStatusPill(label, className) {
        const pill = document.createElement('span');
        pill.className = `status-pill ${className}`;
        pill.textContent = label;
        return pill;
    }

    function updateOverview() {
        const stats = state.stats;
        const analytics = state.analytics;
        const cost = analytics.cost || {};
        const circuits = analytics.circuit_counts || {};

        setMetric('total-requests', formatNumber(stats.total_requests));
        setMetric('top-provider', stats.top_provider || 'none');
        setMetric('success-rate', formatPercent(stats.success_rate));
        setMetric('failed-requests', formatNumber(stats.failed_requests));
        setMetric('p95-latency', formatLatency(stats.p95_response_time));
        setMetric('p50-latency', Math.round(Number(stats.p50_response_time || 0)));
        setMetric('estimated-cost', formatCost(cost.effective_cost));
        setMetric('cost-coverage', formatPercent(cost.coverage_percent));
        setMetric('active-providers', formatNumber(analytics.active_providers));
        setMetric('configured-providers', formatNumber(analytics.configured_providers));
        setMetric('open-circuits', formatNumber(circuits.open));
        setMetric('providers-with-traffic', formatNumber(analytics.providers_with_traffic));
    }

    function updateUptime() {
        const node = document.getElementById('uptime');
        const startedAt = Number(state.system.uptime_start_seconds || 0);
        if (!node || !startedAt) {
            return;
        }
        const seconds = Math.max(0, Math.floor(Date.now() / 1000) - startedAt);
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        node.textContent = days ? `${days}d ${hours}h` : `${hours}h ${minutes}m`;
    }

    function updateLastRefreshed() {
        const node = document.getElementById('last-updated');
        if (node) {
            node.textContent = new Date().toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        }
    }

    function renderTrafficChart() {
        const container = document.getElementById('traffic-chart');
        const series = state.stats.traffic_series || [];
        if (!container) {
            return;
        }
        container.replaceChildren();
        const maximum = Math.max(
            ...series.map((bucket) => Number(bucket.requests || 0)),
            1
        );

        series.forEach((bucket, index) => {
            const requests = Number(bucket.requests || 0);
            const errors = Number(bucket.errors || 0);
            const column = document.createElement('div');
            const bar = document.createElement('span');
            const errorBar = document.createElement('span');
            column.className = 'traffic-column';
            column.setAttribute(
                'aria-label',
                `${bucket.label}: ${requests} requests, ${errors} errors`
            );
            bar.className = 'traffic-column__bar';
            bar.style.height = `${Math.max(requests ? 2 : 0, (requests / maximum) * 100)}%`;
            errorBar.className = 'traffic-column__error';
            errorBar.style.height = `${Math.max(errors ? 2 : 0, (errors / maximum) * 100)}%`;
            column.append(bar, errorBar);

            if (index % 4 === 0 || index === series.length - 1) {
                const label = document.createElement('span');
                label.className = 'traffic-column__label';
                label.textContent = bucket.label === '-0h' ? 'now' : bucket.label;
                column.appendChild(label);
            }
            container.appendChild(column);
        });
    }

    function renderStatusBreakdown() {
        const container = document.getElementById('status-breakdown');
        const breakdown = state.stats.status_code_breakdown || {};
        if (!container) {
            return;
        }
        container.replaceChildren();
        const total = Object.values(breakdown).reduce(
            (sum, value) => sum + Number(value || 0),
            0
        );

        ['2xx', '3xx', '4xx', '5xx', 'other'].forEach((bucket) => {
            const value = Number(breakdown[bucket] || 0);
            const share = total ? (value / total) * 100 : 0;
            const row = document.createElement('div');
            const label = document.createElement('strong');
            const track = document.createElement('span');
            const bar = document.createElement('span');
            const amount = document.createElement('span');
            row.className = 'status-breakdown__row';
            label.textContent = bucket;
            track.className = 'progress-track';
            bar.style.width = `${share}%`;
            track.appendChild(bar);
            amount.textContent = `${share.toFixed(1)}%`;
            row.append(label, track, amount);
            container.appendChild(row);
        });
    }

    function providerSort(left, right) {
        const leftTraffic = Number(left[1].requests_24h || 0);
        const rightTraffic = Number(right[1].requests_24h || 0);
        const leftReady = left[1].active ? 1 : 0;
        const rightReady = right[1].active ? 1 : 0;
        return rightReady - leftReady || rightTraffic - leftTraffic || left[0].localeCompare(right[0]);
    }

    function createProviderCell(provider, details) {
        const cell = document.createElement('td');
        const wrapper = document.createElement('span');
        const glyph = document.createElement('span');
        const copy = document.createElement('span');
        const name = document.createElement('strong');
        const status = document.createElement('small');
        wrapper.className = 'provider-cell';
        glyph.className = 'provider-glyph';
        glyph.textContent = provider.slice(0, 2).toUpperCase();
        name.textContent = details.name || provider;
        status.textContent = details.is_configured ? 'configured' : 'not configured';
        copy.append(name, status);
        wrapper.append(glyph, copy);
        cell.appendChild(wrapper);
        return cell;
    }

    function renderProviderHealth() {
        const body = document.getElementById('provider-health-body');
        if (!body) {
            return;
        }
        body.replaceChildren();
        Object.entries(state.providers).sort(providerSort).forEach(([provider, details]) => {
            const circuit = details.circuit || { state: 'closed' };
            const circuitLabel = circuit.mode === 'bypassed'
                ? 'passthrough'
                : circuit.mode === 'mixed'
                    ? `${circuit.state} · mixed`
                    : circuit.state;
            const row = document.createElement('tr');
            const circuitCell = document.createElement('td');
            circuitCell.appendChild(
                createStatusPill(
                    circuitLabel,
                    circuit.mode === 'bypassed'
                        ? 'tone-neutral'
                        : safeStateClass(circuit.state)
                )
            );
            row.append(
                createProviderCell(provider, details),
                circuitCell,
                createTextCell(formatPercent(details.success_rate)),
                createTextCell(formatNumber(details.requests_24h)),
                createTextCell(formatLatency(details.avg_latency)),
                createTextCell(formatLatency(details.p95_latency)),
                createTextCell(relativeTime(details.last_request_at))
            );
            body.appendChild(row);
        });
    }

    function traceSource() {
        if (state.requests.length) {
            return state.requests.slice(0, 6).map((record) => ({
                provider: record.provider,
                status_code: record.status_code,
                model: record.model,
                time: record.time,
                request_id: record.request_id
            }));
        }
        return state.recentActivity.slice(0, 6);
    }

    function renderRouteTrace() {
        const container = document.getElementById('route-trace');
        const count = document.getElementById('trace-count');
        const events = traceSource();
        if (!container) {
            return;
        }
        container.replaceChildren();
        if (count) {
            count.textContent = `${events.length} events`;
        }
        if (!events.length) {
            const empty = document.createElement('div');
            empty.className = 'empty-state';
            empty.textContent = 'No request traces yet.';
            container.appendChild(empty);
            return;
        }

        events.forEach((event, index) => {
            const item = document.createElement('div');
            const position = document.createElement('span');
            const copy = document.createElement('span');
            const title = document.createElement('strong');
            const detail = document.createElement('small');
            const status = Number(event.status_code || (event.status === 'success' ? 200 : 500));
            item.className = 'trace-item';
            position.className = 'trace-item__index';
            position.textContent = String(index + 1).padStart(2, '0');
            title.textContent = `${event.provider || 'unknown'} → ${status}`;
            detail.textContent = event.model || event.request_id || relativeTime(event.time);
            copy.append(title, detail);
            item.append(
                position,
                copy,
                createStatusPill(
                    status < 400 ? 'ok' : 'error',
                    status < 400 ? 'tone-positive' : 'tone-danger'
                )
            );
            container.appendChild(item);
        });
    }

    function renderCostSummary() {
        const cost = state.analytics.cost || {};
        const total = document.getElementById('cost-total');
        const list = document.getElementById('cost-list');
        const empty = document.getElementById('cost-empty');
        const providerCosts = cost.provider_costs || [];
        if (total) {
            total.textContent = formatCost(cost.effective_cost, 6);
        }
        if (!list || !empty) {
            return;
        }
        list.replaceChildren();
        empty.hidden = providerCosts.length > 0;
        providerCosts.slice(0, 6).forEach((provider) => {
            const item = document.createElement('div');
            const glyph = document.createElement('span');
            const copy = document.createElement('span');
            const name = document.createElement('strong');
            const detail = document.createElement('small');
            const amount = document.createElement('strong');
            item.className = 'cost-item';
            glyph.className = 'provider-glyph';
            glyph.textContent = provider.provider.slice(0, 2).toUpperCase();
            name.textContent = provider.provider;
            detail.textContent = `${formatNumber(provider.requests)} priced requests`;
            amount.textContent = formatCost(provider.effective_cost, 6);
            copy.append(name, detail);
            item.append(glyph, copy, amount);
            list.appendChild(item);
        });
    }

    function requestMatches(record) {
        const search = document.getElementById('request-search')?.value.trim().toLowerCase() || '';
        const provider = document.getElementById('request-provider-filter')?.value || '';
        const status = document.getElementById('request-status-filter')?.value || '';
        const haystack = [
            record.request_id,
            record.model,
            record.user_id,
            record.api_key_prefix,
            record.endpoint
        ].filter(Boolean).join(' ').toLowerCase();
        const statusMatches = !status
            || (status === 'success' && Number(record.status_code) < 400)
            || (status === 'error' && Number(record.status_code) >= 400);
        return (!search || haystack.includes(search))
            && (!provider || record.provider === provider)
            && statusMatches;
    }

    function createRequestIdentityCell(record) {
        const cell = document.createElement('td');
        const time = document.createElement('strong');
        const requestId = document.createElement('code');
        time.textContent = record.time || '—';
        requestId.textContent = record.request_id || 'no request id';
        time.style.display = 'block';
        requestId.style.display = 'block';
        cell.append(time, requestId);
        return cell;
    }

    function createRequestRouteCell(record) {
        const cell = document.createElement('td');
        const provider = document.createElement('strong');
        const endpoint = document.createElement('code');
        const decision = document.createElement('small');
        provider.textContent = record.provider || 'unknown';
        endpoint.textContent = record.endpoint || '—';
        decision.textContent = record.route_decision || 'unknown decision';
        provider.style.display = 'block';
        endpoint.style.display = 'block';
        decision.style.display = 'block';
        cell.append(provider, endpoint, decision);
        return cell;
    }

    function renderRequests() {
        const body = document.getElementById('request-log-body');
        const empty = document.getElementById('request-log-empty');
        if (!body || !empty) {
            return;
        }
        body.replaceChildren();
        const records = state.requests.filter(requestMatches);
        empty.hidden = records.length > 0;

        records.forEach((record) => {
            const row = document.createElement('tr');
            const statusCell = document.createElement('td');
            const circuitCell = document.createElement('td');
            const statusCode = Number(record.status_code || 0);
            statusCell.appendChild(
                createStatusPill(
                    String(statusCode),
                    statusCode < 400 ? 'tone-positive' : 'tone-danger'
                )
            );
            circuitCell.appendChild(
                createStatusPill(
                    record.circuit_state || 'unknown',
                    safeStateClass(record.circuit_state)
                )
            );
            row.append(
                createRequestIdentityCell(record),
                createRequestRouteCell(record),
                createTextCell(record.model || '—'),
                statusCell,
                createTextCell(formatLatency(record.response_time)),
                circuitCell,
                createTextCell(
                    record.actual_cost != null
                        ? formatCost(record.actual_cost, 6)
                        : record.estimated_cost != null
                            ? formatCost(record.estimated_cost, 6)
                            : 'unpriced'
                )
            );
            body.appendChild(row);
        });
        renderRouteTrace();
    }

    function populateProviderFilter() {
        const select = document.getElementById('request-provider-filter');
        if (!select || select.options.length > 1) {
            return;
        }
        Object.keys(state.providers).sort().forEach((provider) => {
            const option = document.createElement('option');
            option.value = provider;
            option.textContent = provider;
            select.appendChild(option);
        });
    }

    async function fetchRequests() {
        if (!isAdmin) {
            const empty = document.getElementById('request-log-empty');
            if (empty) {
                empty.hidden = false;
                empty.querySelector('strong').textContent = 'Admin access required';
                empty.querySelector('p').textContent = 'Request-level telemetry is restricted to dashboard administrators.';
            }
            return;
        }
        try {
            const response = await fetch(root.dataset.requestLog, {
                credentials: 'same-origin',
                headers: { Accept: 'application/json' }
            });
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const payload = await response.json();
            state.requests = payload.requests || [];
            renderRequests();
        } catch (error) {
            console.error('Request telemetry refresh failed:', error);
            window.MultiLLM?.showToast('Request telemetry could not be refreshed', 'error');
        }
    }

    function renderAll() {
        updateOverview();
        updateUptime();
        renderTrafficChart();
        renderStatusBreakdown();
        renderProviderHealth();
        renderRouteTrace();
        renderCostSummary();
        populateProviderFilter();
        updateLastRefreshed();
    }

    function parseEvent(event) {
        try {
            return JSON.parse(event.data);
        } catch (error) {
            console.error('Status stream event was invalid:', error);
            return null;
        }
    }

    function setStreamState(label, connected) {
        const node = document.getElementById('stream-state');
        if (!node) {
            return;
        }
        node.textContent = label;
        node.classList.toggle('tone-warning', !connected);
    }

    function startStatusStream() {
        if (!window.EventSource) {
            setStreamState('Polling only', false);
            return;
        }
        const source = new EventSource(root.dataset.statusStream);
        source.onopen = () => setStreamState('Live stream', true);
        source.onerror = () => setStreamState('Reconnecting', false);
        source.addEventListener('system', (event) => {
            const payload = parseEvent(event);
            if (payload) {
                state.system = payload;
                updateUptime();
                updateLastRefreshed();
            }
        });
        source.addEventListener('stats', (event) => {
            const payload = parseEvent(event);
            if (payload) {
                state.stats = payload;
                updateOverview();
                renderTrafficChart();
                renderStatusBreakdown();
                updateLastRefreshed();
            }
        });
        source.addEventListener('activity', (event) => {
            const payload = parseEvent(event);
            if (payload) {
                state.recentActivity = payload;
                renderRouteTrace();
            }
        });
        source.addEventListener('providers', (event) => {
            const payload = parseEvent(event);
            if (payload) {
                state.providers = payload;
                renderProviderHealth();
            }
        });
        source.addEventListener('analytics', (event) => {
            const payload = parseEvent(event);
            if (payload) {
                state.analytics = payload;
                updateOverview();
                renderCostSummary();
            }
        });
    }

    ['request-search', 'request-provider-filter', 'request-status-filter'].forEach((id) => {
        document.getElementById(id)?.addEventListener('input', renderRequests);
        document.getElementById(id)?.addEventListener('change', renderRequests);
    });
    document.getElementById('refresh-requests')?.addEventListener('click', fetchRequests);

    renderAll();
    fetchRequests();
    startStatusStream();
    window.setInterval(updateUptime, 30_000);
    window.setInterval(fetchRequests, 30_000);
}());
