/**
 * OpenRouter dashboard integration.
 * Provider credentials stay server-side; browser requests use the Flask session.
 */
(function initializeOpenRouterLab() {
    const root = document.getElementById('openrouter-lab');
    const responseArea = document.getElementById('response-area');
    if (!root || !responseArea) {
        return;
    }

    const modelInput = document.getElementById('model-input');
    const promptInput = document.getElementById('prompt-input');
    const streamingToggle = document.getElementById('streaming-toggle');
    const selectedModelDisplay = document.getElementById('selected-model-display');
    const testButton = document.getElementById('test-button');
    const stopButton = document.getElementById('stop-button');
    const copyButton = document.getElementById('copy-response');
    let activeRequest = null;

    function getCsrfToken() {
        const tokenElement = document.querySelector('meta[name="csrf-token"]');
        return tokenElement ? tokenElement.getAttribute('content') : '';
    }

    function dashboardFetch(url, options) {
        const headers = new Headers(options.headers || {});
        const csrfToken = getCsrfToken();
        if (csrfToken) {
            headers.set('X-CSRFToken', csrfToken);
        }
        return fetch(url, {
            ...options,
            credentials: 'same-origin',
            headers
        });
    }

    function setPlainText(element, text, className) {
        if (!element) {
            return;
        }
        element.replaceChildren();
        const wrapper = document.createElement('div');
        if (className) {
            wrapper.className = className;
        }
        wrapper.textContent = text;
        element.appendChild(wrapper);
        return wrapper;
    }

    function setResponseText(text, className) {
        const wrapper = setPlainText(responseArea, text, className);
        responseArea.scrollTop = responseArea.scrollHeight;
        return wrapper;
    }

    function setLoading(isLoading) {
        document.getElementById('response-status')?.classList.toggle('hidden', !isLoading);
        if (stopButton) stopButton.disabled = !isLoading;
        if (testButton) {
            testButton.disabled = isLoading || root.dataset.admin !== 'true';
            testButton.textContent = isLoading ? 'Running…' : 'Run request';
        }
    }

    function updateTokensInfo(usage) {
        const tokensInfo = document.getElementById('tokens-info');
        if (!tokensInfo || !usage) {
            return;
        }
        const promptTokens = Number(usage.prompt_tokens || 0);
        const completionTokens = Number(usage.completion_tokens || 0);
        const totalTokens = Number(usage.total_tokens || 0);
        tokensInfo.textContent = `Tokens: ${promptTokens} prompt + ${completionTokens} completion = ${totalTokens} total`;
    }

    function onSseEventBlock(eventBlock, onData) {
        const dataLines = eventBlock
            .split(/\r?\n/)
            .map((line) => line.trimEnd())
            .filter((line) => line && !line.startsWith(':') && line.startsWith('data:'))
            .map((line) => line.slice(5).trimStart());

        if (!dataLines.length) {
            return false;
        }
        const payload = dataLines.join('\n');
        if (payload === '[DONE]') {
            return true;
        }
        const parsed = JSON.parse(payload);
        if (parsed.error) throw new Error(parsed.error.message || 'Provider stream failed');
        onData(parsed);
        return false;
    }

    async function readSseStream(response, onData, signal) {
        if (!response.body) throw new Error('The provider returned no response body');
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        let terminated = false;
        const consume = (block) => onSseEventBlock(block, (data) => {
            if (data.choices?.some((choice) => choice.finish_reason)) terminated = true;
            onData(data);
        });
        const abort = () => { void reader.cancel().catch(() => {}); };
        signal.addEventListener('abort', abort, { once: true });
        try {
            while (true) {
                signal.throwIfAborted();
                const { done, value } = await reader.read();
                signal.throwIfAborted();
                if (done) break;
                buffer += decoder.decode(value, { stream: true });
                const events = buffer.split(/\r?\n\r?\n/);
                buffer = events.pop() || '';
                for (const eventBlock of events) {
                    if (consume(eventBlock)) return;
                }
            }
            buffer += decoder.decode();
            if (buffer.trim() && consume(buffer)) return;
            if (!terminated) throw new Error('Stream ended before completion. Partial output is preserved.');
        } finally {
            signal.removeEventListener('abort', abort);
            void reader.cancel().catch(() => {});
            reader.releaseLock();
        }
    }

    async function testOpenRouterModel(model, prompt, stream) {
        if (activeRequest) return;
        activeRequest = new AbortController();
        let pendingText = '';
        let outputNode;
        let renderFrame;
        const flush = () => {
            if (renderFrame !== undefined) window.cancelAnimationFrame(renderFrame);
            renderFrame = undefined;
            if (outputNode && pendingText) {
                outputNode.appendData(pendingText);
                pendingText = '';
                responseArea.scrollTop = responseArea.scrollHeight;
            }
        };
        setResponseText('Generating response…', 'response-placeholder');
        setLoading(true);
        try {
            const response = await dashboardFetch('/dashboard/openrouter/chat-completions', {
                method: 'POST',
                signal: activeRequest.signal,
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': stream ? 'text/event-stream' : 'application/json'
                },
                body: JSON.stringify({
                    model,
                    messages: [{ role: 'user', content: prompt }],
                    stream
                })
            });
            if (!response.ok) {
                const errorPayload = await response.json().catch(() => ({}));
                throw new Error(errorPayload.message || errorPayload.error?.message ||
                    (typeof errorPayload.error === 'string' ? errorPayload.error : `HTTP error ${response.status}`));
            }

            if (stream) {
                const output = setResponseText('');
                outputNode = document.createTextNode('');
                output.appendChild(outputNode);
                await readSseStream(response, (data) => {
                    const content = data.choices?.[0]?.delta?.content;
                    if (content) {
                        pendingText += content;
                        if (renderFrame === undefined) renderFrame = window.requestAnimationFrame(flush);
                    }
                    if (data.usage) {
                        updateTokensInfo(data.usage);
                    }
                }, activeRequest.signal);
            } else {
                const data = await response.json();
                const content = data.choices?.[0]?.message?.content
                    ?? JSON.stringify(data, null, 2);
                setResponseText(content);
                updateTokensInfo(data.usage);
            }
            updateOpenRouterCredits();
        } catch (error) {
            flush();
            const message = activeRequest.signal.aborted ? 'Stopped. Partial output is preserved.' : `Error: ${error.message}`;
            if (outputNode) {
                const notice = document.createElement('p');
                notice.className = 'tone-danger';
                notice.setAttribute('role', 'status');
                notice.textContent = message;
                responseArea.appendChild(notice);
            } else setResponseText(message, 'tone-danger');
        } finally {
            flush();
            activeRequest = null;
            setLoading(false);
        }
    }

    function setCreditsDisplay(message, tone) {
        const creditsDisplay = document.getElementById('credits-display');
        if (!creditsDisplay) {
            return;
        }
        creditsDisplay.textContent = message;
        creditsDisplay.style.color = tone === 'error' ? 'var(--rose-700)' : 'var(--ink-950)';
    }

    function renderCredits(data) {
        const creditsPayload = data?.data ?? data ?? {};
        const used = Number(creditsPayload.usage ?? creditsPayload.used ?? 0);
        const hasLimit = creditsPayload.limit !== undefined && creditsPayload.limit !== null;
        const limit = hasLimit
            ? Number(creditsPayload.limit)
            : Number(creditsPayload.credit ?? creditsPayload.credits ?? 0) + used;
        const available = creditsPayload.limit_remaining !== undefined && creditsPayload.limit_remaining !== null
            ? Number(creditsPayload.limit_remaining)
            : Math.max(limit - used, 0);
        const percentage = limit > 0 ? Math.min(Math.round((used / limit) * 100), 100) : 0;

        setCreditsDisplay(
            hasLimit || limit > 0
                ? `$${available.toFixed(2)}`
                : 'Credits Available: Unlimited',
            'ok'
        );
        document.getElementById('usage-bar').style.width = `${percentage}%`;
        document.getElementById('usage-percentage').textContent = `${percentage}%`;
        document.getElementById('usage-details').textContent = limit > 0
            ? `$${used.toFixed(2)} used of $${limit.toFixed(2)} reported limit.`
            : 'No OpenRouter credit usage has been reported for this key.';
    }

    async function updateOpenRouterCredits() {
        if (root.dataset.admin !== 'true') {
            setCreditsDisplay('Restricted', 'error');
            return;
        }
        try {
            const response = await dashboardFetch('/dashboard/openrouter/credits', {
                method: 'GET',
                headers: { 'Accept': 'application/json' }
            });
            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }
            renderCredits(await response.json());
        } catch (error) {
            console.error('Error fetching OpenRouter credits:', error);
            setCreditsDisplay('Unavailable', 'error');
        }
    }

    document.querySelectorAll('.model-button').forEach((button) => {
        button.addEventListener('click', () => {
            document.querySelectorAll('.model-button').forEach((candidate) => {
                candidate.classList.toggle('is-selected', candidate === button);
            });
            modelInput.value = button.dataset.model;
            selectedModelDisplay.textContent = `Selected model: ${button.dataset.model}`;
        });
    });

    modelInput?.addEventListener('input', () => {
        selectedModelDisplay.textContent = modelInput.value.trim()
            ? `Selected model: ${modelInput.value.trim()}`
            : 'Enter a model ID';
        document.querySelectorAll('.model-button').forEach((button) => {
            button.classList.toggle('is-selected', button.dataset.model === modelInput.value.trim());
        });
    });

    testButton?.addEventListener('click', () => {
        const model = modelInput?.value.trim() || '';
        const prompt = promptInput?.value.trim() || '';
        if (!model || !prompt) {
            window.MultiLLM?.showToast('Enter both a model ID and prompt', 'error');
            return;
        }
        return testOpenRouterModel(model, prompt, Boolean(streamingToggle?.checked));
    });

    stopButton?.addEventListener('click', () => activeRequest?.abort());
    window.addEventListener('pagehide', () => activeRequest?.abort());

    copyButton?.addEventListener('click', async () => {
        try {
            if (!await window.MultiLLM.copyText(responseArea.textContent || '')) {
                throw new Error('Clipboard copy was rejected');
            }
            window.MultiLLM.showToast('Response copied');
        } catch (error) {
            window.MultiLLM?.showToast('Could not copy response', 'error');
        }
    });

    updateOpenRouterCredits();
}());
