export class NotificationManager {
    constructor() {
        this.container = document.getElementById('notificationContainer');
        if (!this.container) {
            this.createContainer();
        }
    }

    createContainer() {
        this.container = document.createElement('div');
        this.container.id = 'notificationContainer';
        this.container.setAttribute('role', 'alert');
        this.container.setAttribute('aria-live', 'polite');
        this.container.className = 'fixed top-4 right-4 z-50 space-y-2';
        document.body.appendChild(this.container);
    }

    show(message, type = 'success', duration = 3000) {
        const notification = document.createElement('div');
        notification.className = `
            notification transform translate-y-0 opacity-100
            p-4 rounded-lg shadow-lg max-w-sm
            ${type === 'success' ? 'bg-success text-white' : 'bg-error text-white'}
            transition-all duration-300 ease-in-out
        `;
        
        notification.innerHTML = `
            <div class="flex items-center">
                <i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'} mr-2" 
                   aria-hidden="true"></i>
                <span class="font-medium">${message}</span>
            </div>
        `;

        this.container.appendChild(notification);

        // Animate out and remove
        setTimeout(() => {
            notification.classList.add('translate-y-2', 'opacity-0');
            setTimeout(() => notification.remove(), 300);
        }, duration);
    }
} 