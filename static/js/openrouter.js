/**
 * OpenRouter integration for MultiLLM-Proxy
 * Handles the OpenRouter dashboard functionality
 */
document.addEventListener('DOMContentLoaded', function() {
    // Only initialize if we're on the OpenRouter page
    if (document.getElementById('response-area')) {
        initOpenRouterDashboard();
    }
});

/**
 * Initialize the OpenRouter dashboard functionality
 */
function initOpenRouterDashboard() {
    const modelButtons = document.querySelectorAll('.model-button');
    const testButton = document.getElementById('test-button');
    const responseArea = document.getElementById('response-area');
    const promptInput = document.getElementById('prompt-input');
    const streamingToggle = document.getElementById('streaming-toggle');
    const selectedModelDisplay = document.getElementById('selected-model-display');
    const copyButton = document.getElementById('copy-response');
    const responseStatus = document.getElementById('response-status');
    
    // Set default selected model
    let selectedModel = '';
    
    // Add click handlers to model buttons
    modelButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Remove active class from all buttons
            modelButtons.forEach(btn => {
                btn.classList.remove('bg-indigo-600', 'text-white');
                btn.classList.add('bg-white', 'text-gray-700');
            });
            
            // Add active class to clicked button
            this.classList.add('bg-indigo-600', 'text-white');
            this.classList.remove('bg-white', 'text-gray-700');
            
            // Update selected model
            selectedModel = this.getAttribute('data-model');
            selectedModelDisplay.textContent = `Selected model: ${selectedModel}`;
            
            // Enable test button
            testButton.disabled = false;
        });
    });
    
    // Add test button click handler
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
    
    // Add copy button handler
    if (copyButton) {
        copyButton.addEventListener('click', function() {
            const text = responseArea.innerText;
            navigator.clipboard.writeText(text).then(() => {
                const originalText = copyButton.innerHTML;
                copyButton.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" /></svg>Copied!';
                setTimeout(() => {
                    copyButton.innerHTML = originalText;
                }, 2000);
            });
        });
    }
    
    // Initialize credits display
    updateOpenRouterCredits();
}

/**
 * Test an OpenRouter model with the given prompt
 * 
 * @param {string} model - The model identifier (e.g., "openai/gpt-4o")
 * @param {string} prompt - The prompt to send to the model
 * @param {boolean} stream - Whether to use streaming
 */
function testOpenRouterModel(model, prompt, stream) {
    const responseArea = document.getElementById('response-area');
    const responseStatus = document.getElementById('response-status');
    const tokensInfo = document.getElementById('tokens-info');
    
    // Show loading state
    responseArea.innerHTML = '<div class="text-gray-400 italic">Generating response...</div>';
    responseStatus.classList.remove('hidden');
    responseStatus.classList.add('flex');
    
    // Get authorization token (assuming it's stored in session)
    const apiKey = 'MjM0NTY3ODkwMTI'; // Admin key
    
    // Prepare request payload
    const payload = {
        model: model,
        messages: [
            { 
                role: "user", 
                content: prompt 
            }
        ],
        stream: stream
    };
    
    if (stream) {
        // Handle streaming
        const eventSource = new EventSource(`/openrouter/chat/completions?stream=true&model=${encodeURIComponent(model)}`);
        
        let responseText = '';
        responseArea.innerHTML = '';
        
        eventSource.onmessage = function(event) {
            // Parse the event data as JSON
            try {
                if (event.data === "[DONE]") {
                    eventSource.close();
                    responseStatus.classList.remove('flex');
                    responseStatus.classList.add('hidden');
                    return;
                }
                
                const data = JSON.parse(event.data);
                
                // Extract the content from the response
                if (data.choices && data.choices[0].delta && data.choices[0].delta.content) {
                    const content = data.choices[0].delta.content;
                    responseText += content;
                    
                    // Format the response text with proper Markdown
                    responseArea.innerHTML = formatResponse(responseText);
                    
                    // Auto-scroll to bottom
                    responseArea.scrollTop = responseArea.scrollHeight;
                }
                
                // Update usage information if available
                if (data.usage) {
                    updateTokensInfo(data.usage);
                }
            } catch (error) {
                console.error('Error parsing streaming response:', error);
            }
        };
        
        eventSource.onerror = function(error) {
            eventSource.close();
            responseArea.innerHTML = `<div class="text-red-500">Error: ${error.message || 'Failed to connect to the server'}</div>`;
            responseStatus.classList.remove('flex');
            responseStatus.classList.add('hidden');
        };
        
        // Send request to initialize streaming
        fetch('/openrouter/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify(payload)
        }).catch(error => {
            eventSource.close();
            responseArea.innerHTML = `<div class="text-red-500">Error: ${error.message}</div>`;
            responseStatus.classList.remove('flex');
            responseStatus.classList.add('hidden');
        });
    } else {
        // Regular non-streaming request
        fetch('/openrouter/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify(payload)
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            // Extract response content
            const content = data.choices && data.choices[0].message 
                ? data.choices[0].message.content 
                : JSON.stringify(data, null, 2);
            
            // Display the response
            responseArea.innerHTML = formatResponse(content);
            
            // Update usage information if available
            if (data.usage) {
                updateTokensInfo(data.usage);
            }
            
            // Hide loading state
            responseStatus.classList.remove('flex');
            responseStatus.classList.add('hidden');
            
            // Update credits after completion
            updateOpenRouterCredits();
        })
        .catch(error => {
            responseArea.innerHTML = `<div class="text-red-500">Error: ${error.message}</div>`;
            responseStatus.classList.remove('flex');
            responseStatus.classList.add('hidden');
        });
    }
}

/**
 * Format response text for display
 * 
 * @param {string} text - The response text to format
 * @returns {string} - Formatted HTML
 */
function formatResponse(text) {
    // Convert bullet points to HTML
    text = text.replace(/•\s(.*?)(?=\n•|\n\n|$)/gs, '<li>$1</li>');
    text = text.replace(/\n\s*-\s(.*?)(?=\n\s*-|\n\n|$)/gs, '<li>$1</li>');
    
    // Wrap lists in <ul> tags
    if (text.includes('<li>')) {
        text = '<ul class="list-disc pl-5 mb-3">' + text + '</ul>';
    }
    
    // Convert code blocks
    text = text.replace(/```(\w*)\n([\s\S]*?)```/g, function(match, language, code) {
        return `<pre class="bg-gray-100 p-2 rounded"><code>${code}</code></pre>`;
    });
    
    // Convert inline code
    text = text.replace(/`([^`]+)`/g, '<code>$1</code>');
    
    // Convert newlines to <br> tags outside of lists and code blocks
    text = text.replace(/\n\n/g, '<br><br>');
    text = text.replace(/\n/g, '<br>');
    
    return text;
}

/**
 * Updates the tokens info display
 * 
 * @param {Object} usage - The usage information from the API response
 */
function updateTokensInfo(usage) {
    const tokensInfo = document.getElementById('tokens-info');
    if (tokensInfo && usage) {
        tokensInfo.innerHTML = `
            <span class="font-medium">Tokens:</span> 
            ${usage.prompt_tokens || 0} prompt + 
            ${usage.completion_tokens || 0} completion = 
            ${usage.total_tokens || 0} total
        `;
    }
}

/**
 * Updates the credits display with current OpenRouter credits information
 */
function updateOpenRouterCredits() {
    const apiKey = 'MjM0NTY3ODkwMTI'; // Admin key
    
    fetch('/openrouter/credits', {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${apiKey}`
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        const creditsDisplay = document.getElementById('credits-display');
        const usageBar = document.getElementById('usage-bar');
        const usagePercentage = document.getElementById('usage-percentage');
        const usageDetails = document.getElementById('usage-details');
        
        if (data && data.data) {
            const credits = data.data.credits || 0;
            const used = data.data.used || 0;
            const limit = credits + used;
            
            // Update credits display
            if (creditsDisplay) {
                creditsDisplay.innerHTML = `
                    <svg class="mr-1.5 h-2 w-2 text-green-400" fill="currentColor" viewBox="0 0 8 8">
                        <circle cx="4" cy="4" r="3" />
                    </svg>
                    Credits Available: $${credits.toFixed(2)}
                `;
            }
            
            // Update progress bar
            if (usageBar && usagePercentage && limit > 0) {
                const percentage = Math.min(Math.round((used / limit) * 100), 100);
                usageBar.style.width = `${percentage}%`;
                usagePercentage.textContent = `${percentage}%`;
                
                // Update color based on usage
                if (percentage > 80) {
                    usageBar.classList.add('bg-red-500');
                    usageBar.classList.remove('bg-indigo-500');
                } else {
                    usageBar.classList.add('bg-indigo-500');
                    usageBar.classList.remove('bg-red-500');
                }
            }
            
            // Update usage details
            if (usageDetails) {
                usageDetails.textContent = `You have used $${used.toFixed(2)} out of $${limit.toFixed(2)} total credits allocated to your account.`;
            }
        }
    })
    .catch(error => {
        console.error('Error fetching OpenRouter credits:', error);
        const creditsDisplay = document.getElementById('credits-display');
        if (creditsDisplay) {
            creditsDisplay.innerHTML = `
                <svg class="mr-1.5 h-2 w-2 text-red-400" fill="currentColor" viewBox="0 0 8 8">
                    <circle cx="4" cy="4" r="3" />
                </svg>
                Credits: Error loading
            `;
        }
    });
} 