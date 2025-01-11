// Wait for Vue to be loaded
function initializeVue() {
    if (typeof Vue === 'undefined') {
        console.error('Vue is not loaded yet. Retrying in 100ms...');
        setTimeout(initializeVue, 100);
        return;
    }

    try {
        var pageData = {};
        var pageMethods = {};

        if (window.pageApp) {
            if (typeof window.pageApp.data === 'function') {
                try {
                    pageData = window.pageApp.data();
                } catch (err) {
                    console.error('Error initializing page data:', err);
                    pageData = {};
                }
            }
            if (window.pageApp.methods) {
                pageMethods = window.pageApp.methods;
            }
        }

        const app = Vue.createApp({
            data() {
                return Object.assign({}, pageData);
            },
            methods: Object.assign({}, pageMethods),
            mounted() {
                // Remove v-cloak when Vue is mounted
                this.$el.removeAttribute('v-cloak');
            }
        });
        
        app.mount('#app');
    } catch (err) {
        console.error('Error initializing Vue application:', err);
    }
}

// Start initialization when DOM is loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeVue);
} else {
    initializeVue();
} 