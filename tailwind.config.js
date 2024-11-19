module.exports = {
  darkMode: 'class',
  content: ['./templates/**/*.html', './static/js/**/*.js'],
  theme: {
    extend: {
      colors: {
        primary: {
          DEFAULT: '#4F46E5',
          dark: '#4338CA',
        },
        success: '#10B981',
        error: '#EF4444',
      },
      backgroundColor: {
        dark: {
          primary: '#0F172A',
          secondary: '#1E293B',
        },
        light: {
          primary: '#F8FAFC',
          secondary: '#FFFFFF',
        },
      },
      textColor: {
        dark: {
          primary: '#F8FAFC',
          secondary: '#CBD5E1',
        },
        light: {
          primary: '#0F172A',
          secondary: '#475569',
        },
      },
    },
  },
  plugins: [],
} 