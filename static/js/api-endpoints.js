document.addEventListener('DOMContentLoaded', function() {
    // Provider endpoints configuration
    const endpoints = [
        ['OpenAI', '/openai/v1/chat/completions'],
        ['Groq', '/groq/openai/v1/chat/completions'],
        ['Together AI', '/together/v1/chat/completions'],
        ['Google AI (Gemini)', '/googleai/predict'],
        ['Cerebras', '/cerebras/v1/chat/completions'],
        ['X.AI', '/xai/v1/chat/completions'],
        ['Azure AI', '/azure/v1/chat/completions'],
        ['Scaleway', '/scaleway/chat/completions'],
        ['Hyperbolic', '/hyperbolic/chat/completions'],
        ['SambaNova', ['/sambanova/chat/completions', '/sambanova/completions']],
        ['OpenRouter', ['/openrouter/chat/completions', '/openrouter/models']],
        ['PaLM', '/palm/models/chat-bison-001:generateText'],
        ['Nineteen AI', '/nineteen/v1/completions']
    ];

    function createEndpointElement(provider, endpoint) {
        const div = document.createElement('div');
        div.className = 'relative';
        div.innerHTML = `
            <input type="text" readonly value="http://localhost:1400${endpoint}" 
                   class="w-full p-2 pr-20 bg-gray-50 rounded border focus:outline-none focus:border-blue-500">
            <button onclick="copyEndpoint(this)" 
                    class="absolute right-2 top-1/2 transform -translate-y-1/2 px-3 py-1 bg-blue-500 text-white rounded hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
                Copy
            </button>
        `;
        return div;
    }

    function populateEndpoints() {
        const container = document.getElementById('endpoints-list');
        if (!container) return;

        endpoints.forEach(([provider, endpoint]) => {
            const wrapper = document.createElement('div');
            wrapper.className = 'border rounded-md p-4';
            
            const header = document.createElement('button');
            header.className = 'flex justify-between items-center w-full';
            header.onclick = () => toggleEndpoint(provider);
            header.innerHTML = `
                <span class="font-medium text-gray-900">${provider}</span>
                <svg class="h-5 w-5 transform transition-transform" id="icon-${provider.replace(' ', '-')}" 
                     xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
                </svg>
            `;
            
            const content = document.createElement('div');
            content.className = 'hidden mt-2 space-y-2';
            content.id = `endpoint-${provider.replace(' ', '-')}`;
            
            if (Array.isArray(endpoint)) {
                endpoint.forEach(ep => {
                    content.appendChild(createEndpointElement(provider, ep));
                });
            } else {
                content.appendChild(createEndpointElement(provider, endpoint));
            }
            
            wrapper.appendChild(header);
            wrapper.appendChild(content);
            container.appendChild(wrapper);
        });
    }

    window.toggleEndpoint = function(provider) {
        const content = document.getElementById(`endpoint-${provider.replace(' ', '-')}`);
        const icon = document.getElementById(`icon-${provider.replace(' ', '-')}`);
        if (content && icon) {
            content.classList.toggle('hidden');
            icon.classList.toggle('rotate-180');
        }
    };

    window.copyEndpoint = function(button) {
        const input = button.parentElement.querySelector('input');
        input.select();
        document.execCommand('copy');
        
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        button.classList.remove('bg-blue-500', 'hover:bg-blue-600');
        button.classList.add('bg-green-500', 'hover:bg-green-600');
        
        setTimeout(() => {
            button.textContent = originalText;
            button.classList.remove('bg-green-500', 'hover:bg-green-600');
            button.classList.add('bg-blue-500', 'hover:bg-blue-600');
        }, 2000);
    };

    // Initialize endpoints
    populateEndpoints();
});
