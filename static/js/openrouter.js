/**
 * OpenRouter dashboard integration.
 * Provider credentials stay server-side; browser requests use the Flask session.
 */
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('response-area')) {
        initOpenRouterDashboard();
    }
});

function getCsrfToken() {
    const tokenElement = document.querySelector('meta[name="csrf-token"]');
    return tokenElement ? tokenElement.getAttribute('content') : '';
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
}

function setResponseText(text, className) {
    const responseArea = document.getElementById('response-area');
    setPlainText(responseArea, text, className);
    if (responseArea) {
        responseArea.scrollTop = responseArea.scrollHeight;
    }
}

function setLoading(isLoading) {
    const responseStatus = document.getElementById('response-status');
    if (!responseStatus) {
        return;
    }
    responseStatus.classList.toggle('hidden', !isLoading);
    responseStatus.classList.toggle('flex', isLoading);
}

function dashboardFetch(url, options) {
    const headers = new Headers(options.headers || {});
    const csrfToken = getCsrfToken();
    if (csrfToken) {
        headers.set('X-CSRFToken', csrfToken);
    }
    return fetch(url, {
        ...options,
        headers
    });
}

/**
 * Initialize the OpenRouter dashboard functionality.
 */
function initOpenRouterDashboard() {
    const modelButtons = document.querySelectorAll('.model-button');
    const testButton = document.getElementById('test-button');
    const responseArea = document.getElementById('response-area');
    const promptInput = document.getElementById('prompt-input');
    const streamingToggle = document.getElementById('streaming-toggle');
    const selectedModelDisplay = document.getElementById('selected-model-display');
    const copyButton = document.getElementById('copy-response');

    let selectedModel = '';

    modelButtons.forEach(button => {
        button.addEventListener('click', function() {
            modelButtons.forEach(btn => {
                btn.classList.remove('bg-indigo-600', 'text-white');
                btn.classList.add('bg-white', 'text-gray-700');
            });

            this.classList.add('bg-indigo-600', 'text-white');
            this.classList.remove('bg-white', 'text-gray-700');

            selectedModel = this.getAttribute('data-model');
            selectedModelDisplay.textContent = `Selected model: ${selectedModel}`;
            testButton.disabled = false;
        });
    });

    if (testButton) {
        testButton.addEventListener('click', function() {
            if (!selectedModel) {
                alert('Please select a model first');
                return;
            }

            if (!promptInput.value.trim()) {
                alert('Please enter a prompt');
                return;
            }

            testOpenRouterModel(
                selectedModel,
                promptInput.value,
                streamingToggle.checked
            );
        });
    }

    if (copyButton) {
        copyButton.addEventListener('click', function() {
            const text = responseArea.innerText;
            navigator.clipboard.writeText(text).then(() => {
                const originalText = copyButton.innerHTML;
                copyButton.textContent = 'Copied!';
                setTimeout(() => {
                    copyButton.innerHTML = originalText;
                }, 2000);
            });
        });
    }

    updateOpenRouterCredits();
}

async function readSseStream(response, onData) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
        const { done, value } = await reader.read();
        if (done) {
            break;
        }

        buffer += decoder.decode(value, { stream: true });
        const events = buffer.split(/\r?\n\r?\n/);
        buffer = events.pop() || '';

        for (const eventBlock of events) {
            const shouldStop = onSseEventBlock(eventBlock, onData);
            if (shouldStop) {
                return;
            }
        }
    }

    buffer += decoder.decode();
    if (buffer.trim()) {
        onSseEventBlock(buffer, onData);
    }
}

function onSseEventBlock(eventBlock, onData) {
    const dataLines = eventBlock
        .split(/\r?\n/)
        .map(line => line.trimEnd())
        .filter(line => line && !line.startsWith(':') && line.startsWith('data:'))
        .map(line => line.slice(5).trimStart());

    if (!dataLines.length) {
        return false;
    }

    const payload = dataLines.join('\n');
    if (payload === '[DONE]') {
        return true;
    }

    try {
        onData(JSON.parse(payload));
    } catch (error) {
        console.error('Error parsing streaming response:', error);
    }
    return false;
}

/**
 * Test an OpenRouter model with the given prompt.
 *
 * @param {string} model - The model identifier (e.g., "openai/gpt-4o")
 * @param {string} prompt - The prompt to send to the model
 * @param {boolean} stream - Whether to use streaming
 */
async function testOpenRouterModel(model, prompt, stream) {
    setResponseText('Generating response...', 'text-gray-400 italic');
    setLoading(true);

    const payload = {
        model,
        messages: [
            {
                role: 'user',
                content: prompt
            }
        ],
        stream
    };

    try {
        const response = await dashboardFetch('/dashboard/openrouter/chat-completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': stream ? 'text/event-stream' : 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            throw new Error(`HTTP error ${response.status}`);
        }

        if (stream) {
            let responseText = '';
            setResponseText('');
            await readSseStream(response, data => {
                const content = data.choices && data.choices[0].delta && data.choices[0].delta.content;
                if (content) {
                    responseText += content;
                    setResponseText(responseText);
                }
                if (data.usage) {
                    updateTokensInfo(data.usage);
                }
            });
        } else {
            const data = await response.json();
            const content = data.choices && data.choices[0].message
                ? data.choices[0].message.content
                : JSON.stringify(data, null, 2);
            setResponseText(content);
            if (data.usage) {
                updateTokensInfo(data.usage);
            }
        }

        updateOpenRouterCredits();
    } catch (error) {
        setResponseText(`Error: ${error.message}`, 'text-red-500');
    } finally {
        setLoading(false);
    }
}

/**
 * Updates the tokens info display.
 *
 * @param {Object} usage - The usage information from the API response
 */
function updateTokensInfo(usage) {
    const tokensInfo = document.getElementById('tokens-info');
    if (tokensInfo && usage) {
        const promptTokens = Number(usage.prompt_tokens || 0);
        const completionTokens = Number(usage.completion_tokens || 0);
        const totalTokens = Number(usage.total_tokens || 0);
        tokensInfo.textContent = `Tokens: ${promptTokens} prompt + ${completionTokens} completion = ${totalTokens} total`;
    }
}

function setCreditsDisplay(message, tone) {
    const creditsDisplay = document.getElementById('credits-display');
    if (!creditsDisplay) {
        return;
    }
    const toneClass = tone === 'error' ? 'text-red-800 bg-red-100' : 'text-green-800 bg-green-100';
    creditsDisplay.className = `inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${toneClass}`;
    creditsDisplay.textContent = message;
}

/**
 * Updates the credits display with current OpenRouter credits information.
 */
function updateOpenRouterCredits() {
    dashboardFetch('/dashboard/openrouter/credits', {
        method: 'GET',
        headers: {
            'Accept': 'application/json'
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        const usageBar = document.getElementById('usage-bar');
        const usagePercentage = document.getElementById('usage-percentage');
        const usageDetails = document.getElementById('usage-details');
        const creditsPayload = data && data.data ? data.data : data;
        const credits = Number(creditsPayload.credit || creditsPayload.credits || 0);
        const used = Number(creditsPayload.used || 0);
        const limit = credits + used;

        setCreditsDisplay(`Credits Available: $${credits.toFixed(2)}`, 'ok');

        if (usageBar && usagePercentage && limit > 0) {
            const percentage = Math.min(Math.round((used / limit) * 100), 100);
            usageBar.style.width = `${percentage}%`;
            usagePercentage.textContent = `${percentage}%`;
            usageBar.classList.toggle('bg-red-500', percentage > 80);
            usageBar.classList.toggle('bg-indigo-500', percentage <= 80);
        }

        if (usageDetails) {
            usageDetails.textContent = limit > 0
                ? `You have used $${used.toFixed(2)} out of $${limit.toFixed(2)} total credits allocated to your account.`
                : 'No OpenRouter credit usage has been reported for this key.';
        }
    })
    .catch(error => {
        console.error('Error fetching OpenRouter credits:', error);
        setCreditsDisplay('Credits: Error loading', 'error');
    });
}
