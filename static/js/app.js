import { ThemeManager } from './theme.js';
import { NotificationManager } from './notifications.js';
import { CopyHandler } from './copy-handler.js';

class App {
    constructor() {
        this.notifications = new NotificationManager();
        this.themeManager = new ThemeManager();
        this.copyHandler = new CopyHandler(this.notifications);
        this.initialize();
    }

    initialize() {
        this.setupStatusCheck();
    }

    setupStatusCheck() {
        const checkStatus = async () => {
            try {
                const response = await fetch('/health');
                this.updateStatusIndicator(response.ok);
            } catch {
                this.updateStatusIndicator(false);
            }
        };

        checkStatus();
        setInterval(checkStatus, 30000);
    }

    updateStatusIndicator(isOnline) {
        const indicator = document.getElementById('status-indicator');
        if (!indicator) return;

        const statusClass = isOnline ? 'bg-success' : 'bg-error';
        const statusText = isOnline ? 'System Online' : 'System Offline';

        indicator.innerHTML = `
            <span class="h-3 w-3 ${statusClass} rounded-full mr-2 shadow-sm"></span>
            <span class="text-sm font-medium text-gray-700 dark:text-gray-300">${statusText}</span>
        `;
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    window.app = new App();
}); 