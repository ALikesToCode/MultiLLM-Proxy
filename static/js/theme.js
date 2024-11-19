export class ThemeManager {
    constructor() {
        this.html = document.documentElement;
        this.themeToggle = document.getElementById('themeToggle');
        this.initialize();
    }

    initialize() {
        // Load saved theme or use system preference
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme) {
            this.setTheme(savedTheme);
        } else {
            const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            this.setTheme(systemPrefersDark ? 'dark' : 'light');
        }

        // Add event listeners
        this.themeToggle.addEventListener('click', () => this.toggleTheme());
        this.setupSystemThemeListener();
    }

    setTheme(theme) {
        this.html.className = theme;
        localStorage.setItem('theme', theme);
        
        // Update ARIA label
        this.themeToggle.setAttribute('aria-label', 
            `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`);
    }

    toggleTheme() {
        const currentTheme = this.html.className;
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.body.style.transition = 'background-color 0.3s ease, color 0.3s ease';
        this.setTheme(newTheme);
        
        setTimeout(() => {
            document.body.style.transition = '';
        }, 300);
    }

    setupSystemThemeListener() {
        window.matchMedia('(prefers-color-scheme: dark)')
            .addEventListener('change', e => {
                if (!localStorage.getItem('theme')) {
                    this.setTheme(e.matches ? 'dark' : 'light');
                }
            });
    }
} 