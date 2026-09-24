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

    // A stored credential is configuration, not evidence; only successful traffic verifies a route.
    function providerEvidence(details) {
        if (!Number(details.requests_24h || 0)) {
            return { label: 'no traffic yet', tone: 'tone-unknown' };
        }
        return Number(details.success_rate || 0) > 0
            ? { label: 'recent success', tone: 'tone-positive' }
            : { label: 'failing', tone: 'tone-danger' };
    }

    function isUnpriced(cost) {
        return !cost.basis || cost.basis === 'unpriced';
    }

    function updateOverview() {
        const stats = state.stats;
        const analytics = state.analytics;
        const cost = analytics.cost || {};
        const configured = Object.values(state.providers).filter((details) => details.is_configured);
        const verified = configured.filter((details) => providerEvidence(details).tone === 'tone-positive');

        setMetric('total-requests', formatNumber(stats.total_requests));
        setMetric('top-provider', stats.top_provider || 'none yet');
        setMetric('success-rate', formatPercent(stats.success_rate));
        setMetric('failed-requests', formatNumber(stats.failed_requests));
        setMetric('p95-latency', formatLatency(stats.p95_response_time));
        setMetric('p50-latency', Math.round(Number(stats.p50_response_time || 0)));
        setMetric('estimated-cost', isUnpriced(cost) ? 'Unpriced' : formatCost(cost.effective_cost));
        setMetric('cost-coverage', `${formatPercent(cost.coverage_percent)} of requests priced`);
        setMetric('unpriced-requests', formatNumber(cost.unpriced_requests));
        setMetric('configured-providers', formatNumber(configured.length));
        setMetric('verified-providers', formatNumber(verified.length));
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

    function summarizeTraffic(series) {
        const summary = document.getElementById('traffic-summary');
        if (!summary) {
            return;
        }
        const requests = series.reduce((sum, bucket) => sum + Number(bucket.requests || 0), 0);
        const errors = series.reduce((sum, bucket) => sum + Number(bucket.errors || 0), 0);
        const peak = series.reduce((best, bucket) => (
            Number(bucket.requests || 0) > Number(best?.requests || 0) ? bucket : best
        ), null);
        summary.textContent = requests
            ? `${formatNumber(requests)} requests and ${formatNumber(errors)} errors in the last 24 hours; busiest hour ${peak.label} with ${formatNumber(peak.requests)} requests.`
            : 'No requests in the last 24 hours.';
    }

    function renderTrafficChart() {
        const container = document.getElementById('traffic-chart');
        const series = state.stats.traffic_series || [];
        if (!container) {
            return;
        }
        container.replaceChildren();
        summarizeTraffic(series);
        const maximum = Math.max(
            ...series.map((bucket) => Number(bucket.requests || 0)),
            1
        );
        if (!series.some((bucket) => Number(bucket.requests || 0))) {
            const empty = document.createElement('p');
            empty.className = 'traffic-empty';
            empty.textContent = 'No requests in the last 24 hours.';
            container.appendChild(empty);
            return;
        }

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
            track.dataset.bucket = bucket;
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
        const cell = document.createElement('th');
        const wrapper = document.createElement('span');
        const glyph = document.createElement('span');
        const name = document.createElement('strong');
        cell.scope = 'row';
        wrapper.className = 'provider-cell';
        glyph.className = 'provider-glyph';
        glyph.setAttribute('aria-hidden', 'true');
        glyph.textContent = provider.slice(0, 2).toUpperCase();
        name.textContent = details.name || provider;
        wrapper.append(glyph, name);
        cell.appendChild(wrapper);
        return cell;
    }

    function trafficCell(hasTraffic, value, className = 'numeric') {
        const cell = createTextCell(hasTraffic ? value : '—', className);
        if (!hasTraffic) cell.classList.add('no-data');
        return cell;
    }

    function renderUnconfiguredProviders(entries) {
        const details = document.getElementById('unconfigured-providers');
        const list = document.getElementById('unconfigured-list');
        const count = document.getElementById('unconfigured-count');
        if (!details || !list || !count) {
            return;
        }
        details.hidden = entries.length === 0;
        count.textContent = String(entries.length);
        list.replaceChildren(...entries.map(([provider, info]) => {
            const item = document.createElement('li');
            item.className = 'tag';
            item.textContent = info.name || provider;
            return item;
        }));
    }

    function renderProviderHealth() {
        const body = document.getElementById('provider-health-body');
        if (!body) {
            return;
        }
        body.replaceChildren();
        const entries = Object.entries(state.providers).sort(providerSort);
        const configured = entries.filter(([, details]) => details.is_configured);
        renderUnconfiguredProviders(entries.filter(([, details]) => !details.is_configured));
        const empty = document.getElementById('provider-health-empty');
        if (empty) empty.hidden = configured.length > 0;
        configured.forEach(([provider, details]) => {
            const circuit = details.circuit || { state: 'closed' };
            const circuitLabel = circuit.mode === 'bypassed'
                ? 'passthrough'
                : circuit.mode === 'mixed'
                    ? `${circuit.state} · mixed`
                    : circuit.state;
            const row = document.createElement('tr');
            const evidence = providerEvidence(details);
            const evidenceCell = document.createElement('td');
            const circuitCell = document.createElement('td');
            const hasTraffic = Number(details.requests_24h || 0) > 0;
            evidenceCell.appendChild(createStatusPill(evidence.label, evidence.tone));
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
                evidenceCell,
                circuitCell,
                trafficCell(hasTraffic, formatPercent(details.success_rate)),
                createTextCell(formatNumber(details.requests_24h), 'numeric'),
                trafficCell(hasTraffic, formatLatency(details.p95_latency)),
                trafficCell(Boolean(details.last_request_at), relativeTime(details.last_request_at), 'cell-nowrap')
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
            const empty = document.createElement('li');
            empty.className = 'empty-state';
            empty.textContent = 'No requests recorded yet. New traffic appears here within seconds.';
            container.appendChild(empty);
            return;
        }

        events.forEach((event, index) => {
            const item = document.createElement('li');
            const position = document.createElement('span');
            const copy = document.createElement('span');
            const title = document.createElement('strong');
            const detail = document.createElement('small');
            const status = Number(event.status_code || (event.status === 'success' ? 200 : 500));
            item.className = 'trace-item';
            position.className = 'trace-item__index';
            position.textContent = String(index + 1).padStart(2, '0');
            title.textContent = `${event.provider || 'unknown'} → ${status}`;
            detail.textContent = [event.model || event.request_id, relativeTime(event.time)].filter(Boolean).join(' · ');
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
        const basis = document.getElementById('cost-basis');
        if (total) {
            total.textContent = isUnpriced(cost) ? 'Unpriced' : formatCost(cost.effective_cost, 6);
        }
        if (basis) {
            basis.textContent = {
                provider: 'provider-reported',
                reservation: 'reservation estimate',
                mixed: 'mixed basis'
            }[cost.basis] || 'unpriced';
        }
        if (!list || !empty) {
            return;
        }
        list.replaceChildren();
        empty.hidden = providerCosts.length > 0;
        providerCosts.slice(0, 6).forEach((provider) => {
            const item = document.createElement('li');
            const glyph = document.createElement('span');
            const copy = document.createElement('span');
            const name = document.createElement('strong');
            const detail = document.createElement('small');
            const amount = document.createElement('strong');
            item.className = 'cost-item';
            glyph.className = 'provider-glyph';
            glyph.setAttribute('aria-hidden', 'true');
            glyph.textContent = provider.provider.slice(0, 2).toUpperCase();
            name.textContent = provider.provider;
            detail.textContent = `${formatNumber(provider.requests)} priced requests`;
            amount.textContent = formatCost(provider.effective_cost, 6);
            copy.append(name, detail);
            item.append(glyph, copy, amount);
            list.appendChild(item);
        });
    }

    // Created lazily: request-explorer.js loads before this script in the page.
    const requestExplorer = window.MultiLLMRequestExplorer?.createRequestExplorer({
        cells: { text: createTextCell, pill: createStatusPill, circuitClass: safeStateClass },
        format: { latency: formatLatency, cost: formatCost }
    });

    async function fetchRequests(signal) {
        if (!isAdmin) {
            requestExplorer?.showRestricted();
            return;
        }
        const payload = await fetchSnapshot(root.dataset.requestLog, signal);
        if (!signal.aborted) {
            state.requests = payload.requests || [];
            requestExplorer?.setRecords(state.requests);
            renderRouteTrace();
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
        requestExplorer?.populateProviders(Object.keys(state.providers));
        updateLastRefreshed();
    }

    async function fetchSnapshot(url, signal) {
        const response = await fetch(url, {
            credentials: 'same-origin',
            cache: 'no-store',
            headers: { Accept: 'application/json' },
            signal
        });
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
    }

    function setStreamState(label, state) {
        const node = document.getElementById('stream-state');
        if (!node) {
            return;
        }
        node.textContent = label;
        node.dataset.state = state;
    }

    let pageActive = true;

    function createPoller(load, intervalMs, onError) {
        let timer;
        let controller;
        const visible = () => pageActive && !document.hidden;
        async function refresh() {
            window.clearTimeout(timer);
            if (controller || !visible()) return;
            controller = new AbortController();
            let timedOut = false;
            const deadline = window.setTimeout(() => {
                timedOut = true;
                controller.abort();
            }, 10_000);
            try {
                await load(controller.signal);
            } catch (error) {
                if (visible() && (timedOut || !controller.signal.aborted)) {
                    onError(error);
                }
            } finally {
                window.clearTimeout(deadline);
                controller = null;
                if (visible()) timer = window.setTimeout(refresh, intervalMs);
            }
        }
        return {
            refresh,
            pause() {
                window.clearTimeout(timer);
                controller?.abort();
            }
        };
    }

    const statusPoller = createPoller(async (signal) => {
        const payload = await fetchSnapshot(root.dataset.statusSnapshot, signal);
        if (signal.aborted) return;
        state.system = payload.system || {};
        state.stats = payload.stats || {};
        state.providers = payload.providers || {};
        state.analytics = payload.analytics || {};
        state.recentActivity = payload.recent_activity || [];
        renderAll();
        setStreamState('Live updates', 'live');
    }, 10_000, () => setStreamState('Refresh failed · retrying', 'error'));
    const requestPoller = createPoller(fetchRequests, 30_000, (error) => {
        console.error('Request telemetry refresh failed:', error);
        requestExplorer?.showFailure();
        window.MultiLLM?.showToast('Request telemetry could not be refreshed', 'error');
    });

    function updatePolling() {
        if (pageActive && !document.hidden) {
            statusPoller.refresh();
            requestPoller.refresh();
        } else {
            statusPoller.pause();
            requestPoller.pause();
            setStreamState('Paused', 'paused');
        }
    }

    document.addEventListener('visibilitychange', updatePolling);
    window.addEventListener('pagehide', () => { pageActive = false; updatePolling(); });
    window.addEventListener('pageshow', () => { pageActive = true; updatePolling(); });
    document.getElementById('refresh-requests')?.addEventListener('click', requestPoller.refresh);

    renderAll();
    updatePolling();
    window.setInterval(updateUptime, 30_000);
}());
