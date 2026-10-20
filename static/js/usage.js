(function initializeUsageConsole() {
    const formatNumber = (value) => Number(value || 0).toLocaleString('en-US');
    const formatCost = (value) => {
        const amount = Number(value || 0);
        return `$${amount.toFixed(amount !== 0 && Math.abs(amount) < 0.01 ? 6 : 2)}`;
    };
    const formatLatency = (value) => (value === null || value === undefined ? '–' : formatNumber(value));
    const formatErrors = (row) => `${formatNumber(row.errors)} (${Number(row.error_rate || 0).toFixed(1)}%)`;

    function formatBudget(limit, spent, remaining, resetsAt) {
        if (limit === null || limit === undefined) {
            return `${formatCost(spent)} spent · no limit`;
        }
        return `${formatCost(spent)} of ${formatCost(limit)} · ${formatCost(remaining)} left · resets ${String(resetsAt || '').slice(0, 16).replace('T', ' ')} UTC`;
    }

    window.MultiLLMUsage = Object.freeze({ formatBudget, formatCost, formatErrors, formatLatency, formatNumber });

    const root = typeof document !== 'undefined' ? document.getElementById('usage-console') : null;
    if (!root) {
        return;
    }

    const isAdmin = root.dataset.admin === 'true';
    const status = document.getElementById('usage-status');
    const principalSelect = document.getElementById('usage-principal');
    const daysSelect = document.getElementById('usage-days');
    const knownPrincipals = new Set();

    function cell(text, numeric) {
        const element = document.createElement('td');
        element.textContent = text;
        if (numeric) {
            element.className = 'numeric';
        }
        return element;
    }

    function fillTable(id, rows, columns, emptyText) {
        const body = document.getElementById(id);
        if (!body) {
            return;
        }
        if (!rows.length) {
            const row = document.createElement('tr');
            const empty = cell(emptyText, false);
            empty.colSpan = columns.length;
            row.append(empty);
            body.replaceChildren(row);
            return;
        }
        body.replaceChildren(...rows.map((item) => {
            const row = document.createElement('tr');
            row.append(...columns.map((column) => {
                const value = column(item);
                if (typeof value === 'object' && value !== null) {
                    const element = document.createElement('td');
                    element.append(value);
                    return element;
                }
                return cell(value, column !== columns[0]);
            }));
            return row;
        }));
    }

    function keyButton(principal) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'usage-key-link';
        button.textContent = principal;
        button.addEventListener('click', () => {
            if (principalSelect) {
                principalSelect.value = principal;
                load();
            }
        });
        return button;
    }

    function setText(selector, text) {
        const element = root.querySelector(selector);
        if (element) {
            element.textContent = text;
        }
    }

    function render(data) {
        const totals = data.totals || {};
        setText('[data-total="cost_usd"]', formatCost(totals.cost_usd));
        setText('[data-total="requests"]', formatNumber(totals.requests));
        setText('[data-total="errors"]', formatErrors(totals));
        setText('[data-total="latency"]', `${formatLatency(totals.latency_p50_ms)} / ${formatLatency(totals.latency_p95_ms)} ms`);
        setText('[data-total="tokens"]', `${formatNumber(totals.input_tokens)} / ${formatNumber(totals.output_tokens)}`);

        const budgetPanel = document.getElementById('usage-budget-panel');
        if (budgetPanel) {
            budgetPanel.hidden = !data.budget;
        }
        if (data.budget) {
            const budget = data.budget;
            const controls = data.controls || {};
            setText('[data-budget="daily"]', formatBudget(budget.daily_budget_usd, budget.spent_today_usd, budget.daily_remaining_usd, budget.daily_resets_at));
            setText('[data-budget="monthly"]', formatBudget(budget.monthly_budget_usd, budget.spent_this_month_usd, budget.monthly_remaining_usd, budget.monthly_resets_at));
            setText('[data-budget="models"]', (controls.allowed_models || []).join(', ') || 'Every model');
            setText('[data-budget="expires"]', controls.expires_at ? `${String(controls.expires_at).slice(0, 16).replace('T', ' ')} UTC` : 'Never');
            setText('[data-budget="ips"]', (controls.allowed_ips || []).join(', ') || 'Any address');
        }

        const latency = [(row) => formatLatency(row.latency_p50_ms), (row) => formatLatency(row.latency_p95_ms)];
        fillTable('usage-daily', data.daily || [], [
            (row) => row.day, (row) => formatNumber(row.requests), formatErrors, (row) => formatCost(row.cost_usd), ...latency,
        ], 'No billable requests in this range.');
        fillTable('usage-models', data.models || [], [
            (row) => row.model, (row) => formatNumber(row.requests), formatErrors,
            (row) => `${formatNumber(row.input_tokens)} / ${formatNumber(row.output_tokens)}`, (row) => formatCost(row.cost_usd), ...latency,
        ], 'No billable requests in this range.');
        if (isAdmin) {
            const keysPanel = document.getElementById('usage-keys-panel');
            if (keysPanel) {
                keysPanel.hidden = Boolean(data.principal);
            }
            const principals = data.principals || [];
            fillTable('usage-keys', principals, [
                (row) => keyButton(row.principal), (row) => formatNumber(row.requests), formatErrors, (row) => formatCost(row.cost_usd), ...latency,
            ], 'No billable requests in this range.');
            principals.forEach((row) => {
                if (principalSelect && !knownPrincipals.has(row.principal)) {
                    knownPrincipals.add(row.principal);
                    principalSelect.append(new Option(row.principal, row.principal));
                }
            });
        }
        if (status) {
            const ledger = data.ledger;
            const history = data.history_available === false ? ' Usage history is unavailable right now; showing only live totals.' : '';
            const pending = ledger && ledger.buffered ? ` ${formatNumber(ledger.buffered)} recent requests are still being written.` : '';
            status.textContent = `${data.range.since} to ${data.range.until} (UTC).${pending}${history}`;
        }
    }

    async function load() {
        const params = new URLSearchParams({ days: daysSelect ? daysSelect.value : '30' });
        if (principalSelect && principalSelect.value) {
            params.set('principal', principalSelect.value);
        }
        if (status) {
            status.textContent = 'Loading usage…';
        }
        try {
            const response = await fetch(`${root.dataset.usageEndpoint}?${params}`, {
                credentials: 'same-origin',
                headers: { Accept: 'application/json' },
            });
            const payload = await response.json().catch(() => ({}));
            if (!response.ok) {
                throw new Error(payload.message || payload.error || `HTTP ${response.status}`);
            }
            render(payload);
        } catch (error) {
            if (status) {
                status.textContent = `Usage could not be loaded: ${error.message}`;
            }
        }
    }

    principalSelect?.addEventListener('change', load);
    daysSelect?.addEventListener('change', load);
    const requested = new URLSearchParams(window.location.search).get('principal');
    if (requested && principalSelect) {
        knownPrincipals.add(requested);
        principalSelect.append(new Option(requested, requested));
        principalSelect.value = requested;
    }
    load();
}());
