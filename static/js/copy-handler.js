export class CopyHandler {
    constructor(notificationManager) {
        this.notifications = notificationManager;
        this.initialize();
    }

    initialize() {
        document.addEventListener('click', this.handleClick.bind(this));
        document.addEventListener('keydown', this.handleKeydown.bind(this));
    }

    async handleClick(event) {
        const button = event.target.closest('[data-copy]');
        if (button) {
            await this.copyText(button.dataset.copy);
        }
    }

    handleKeydown(event) {
        if (event.key === 'Enter' || event.key === ' ') {
            const button = event.target.closest('[data-copy]');
            if (button) {
                event.preventDefault();
                this.copyText(button.dataset.copy);
            }
        }
    }

    async copyText(text) {
        try {
            await navigator.clipboard.writeText(text);
            this.notifications.show('Copied to clipboard!', 'success');
        } catch (err) {
            console.error('Failed to copy:', err);
            this.notifications.show('Failed to copy to clipboard', 'error');
        }
    }
} 