/**
 * Operations request explorer: filters, table rows, and the log's loading, empty,
 * filtered-empty, restricted and failure states. dashboard.js owns polling.
 */
(function registerRequestExplorer() {
    const FILTER_IDS = ['request-search', 'request-provider-filter', 'request-status-filter'];
    const PAGE_SIZE = 25;

    function createRequestExplorer({ cells, format }) {
        const byId = (id) => document.getElementById(id);
        let records = [];
        let loaded = false;
        let visibleLimit = PAGE_SIZE;

        function matches(record) {
            const search = byId('request-search')?.value.trim().toLowerCase() || '';
            const provider = byId('request-provider-filter')?.value || '';
            const status = byId('request-status-filter')?.value || '';
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

        function stackedCell(parts) {
            const cell = document.createElement('td');
            parts.forEach(([tag, text]) => {
                const node = document.createElement(tag);
                node.textContent = text;
                cell.appendChild(node);
            });
            return cell;
        }

        function setState(title, detail) {
            const empty = byId('request-log-empty');
            if (!empty) {
                return;
            }
            empty.hidden = !title;
            if (title) {
                empty.querySelector('strong').textContent = title;
                empty.querySelector('p').textContent = detail;
            }
        }

        function costLabel(record) {
            if (record.actual_cost != null) return format.cost(record.actual_cost, 6);
            if (record.estimated_cost != null) return `≈ ${format.cost(record.estimated_cost, 6)}`;
            return 'unpriced';
        }

        function createRow(record) {
            const row = document.createElement('tr');
            const statusCell = document.createElement('td');
            const circuitCell = document.createElement('td');
            const statusCode = Number(record.status_code || 0);
            statusCell.appendChild(cells.pill(String(statusCode), statusCode < 400 ? 'tone-positive' : 'tone-danger'));
            circuitCell.appendChild(cells.pill(record.circuit_state || 'unknown', cells.circuitClass(record.circuit_state)));
            row.append(
                stackedCell([['strong', record.time || '—'], ['code', record.request_id || 'no request id']]),
                stackedCell([
                    ['strong', record.provider || 'unknown'],
                    ['code', record.endpoint || '—'],
                    ['small', record.route_decision || 'route decision not recorded']
                ]),
                cells.text(record.model || '—'),
                statusCell,
                cells.text(format.latency(record.response_time), 'numeric'),
                circuitCell,
                cells.text(costLabel(record), 'numeric')
            );
            return row;
        }

        function render() {
            const body = byId('request-log-body');
            if (!body) {
                return;
            }
            const matching = records.filter(matches);
            const visible = matching.slice(0, visibleLimit);
            body.replaceChildren(...visible.map(createRow));
            renderPaging(visible.length, matching.length);
            if (!loaded) {
                setState('Loading request records…', 'Recent authenticated proxy traffic appears here.');
            } else if (!records.length) {
                setState('No requests recorded yet', 'Authenticated proxy traffic appears here within 30 seconds.');
            } else if (!visible.length) {
                setState('No records match these filters', 'Clear the search or choose another provider or response class.');
            } else {
                setState(null);
            }
        }

        function renderPaging(shown, total) {
            const footer = byId('request-log-paging');
            const summary = byId('request-log-summary');
            if (!footer || !summary) {
                return;
            }
            footer.hidden = total === 0;
            summary.textContent = `Showing ${shown} of ${total} records`;
            const more = byId('request-log-more');
            if (more) more.hidden = shown >= total;
        }

        function populateProviders(providerKeys) {
            const select = byId('request-provider-filter');
            if (!select || select.options.length > 1) {
                return;
            }
            [...providerKeys].sort().forEach((provider) => select.add(new Option(provider, provider)));
        }

        const refilter = () => {
            visibleLimit = PAGE_SIZE;
            render();
        };
        FILTER_IDS.forEach((id) => {
            byId(id)?.addEventListener('input', refilter);
            byId(id)?.addEventListener('change', refilter);
        });
        byId('request-log-more')?.addEventListener('click', () => {
            visibleLimit += PAGE_SIZE;
            render();
        });

        return {
            setRecords(next) {
                records = next;
                loaded = true;
                render();
            },
            showRestricted() {
                setState('Administrator access required', 'Request-level telemetry is restricted to dashboard administrators.');
            },
            showFailure() {
                if (!loaded) {
                    setState('Request records could not be loaded', 'Retrying every 30 seconds. Use Refresh to try now.');
                }
            },
            populateProviders
        };
    }

    window.MultiLLMRequestExplorer = Object.freeze({ createRequestExplorer });
}());
