/**
 * Theme Toggle System
 * v5.1 Advanced HTML Reports (Fixed)
 */

(function() {
    'use strict';
    
    const THEME_KEY = 'mcp-soc-theme';
    let activeTheme = null;
    
    // Auto-detect system preference
    function detectSystemTheme() {
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            return 'dark';
        }
        return 'light';
    }

    function getTheme() {
        if (activeTheme) return activeTheme;
        try {
            // ใช้ detectSystemTheme() หากไม่มีค่าใน localStorage
            activeTheme = localStorage.getItem(THEME_KEY) || detectSystemTheme();
        } catch (error) {
            activeTheme = 'dark';
        }
        return activeTheme;
    }
    
    function setTheme(theme) {
        activeTheme = theme;
        try {
            localStorage.setItem(THEME_KEY, theme);
        } catch (error) {
            // Theme switching still works for this page view without persistence.
        }
        document.documentElement.setAttribute('data-theme', theme);
        updateThemeIcon(theme);
        
        if (window.Chart) {
            updateChartTheme(theme);
        }
    }
    
    function updateThemeIcon(theme) {
        const icon = document.querySelector('.theme-toggle');
        if (icon) {
            const isDark = theme === 'dark';
            icon.className = `theme-toggle bi ${isDark ? 'bi-sun-fill' : 'bi-moon-stars-fill'}`;
            icon.title = isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode';
        }
    }
    
    function updateChartTheme(theme) {
        const isDark = theme === 'dark';
        
        Chart.defaults.color = isDark ? '#e9ecef' : '#212529';
        Chart.defaults.borderColor = isDark ? '#495057' : '#dee2e6';
        
        if (Chart.defaults.plugins && Chart.defaults.plugins.legend) {
            Chart.defaults.plugins.legend.labels.color = isDark ? '#e9ecef' : '#212529';
        }
        
        if (Chart.instances) {
            Object.values(Chart.instances).forEach(chart => {
                if (chart.options && chart.options.scales) {
                    Object.values(chart.options.scales).forEach(scale => {
                        if (scale.ticks) scale.ticks.color = isDark ? '#e9ecef' : '#212529';
                        if (scale.grid) scale.grid.color = isDark ? '#495057' : '#e9ecef';
                    });
                }
                chart.update();
            });
        }
    }
    
    function toggleTheme() {
        const currentTheme = getTheme();
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        setTheme(newTheme);
    }
    
    function initTheme() {
        const theme = getTheme();
        setTheme(theme);
    }
    
    // Listen for system theme changes
    if (window.matchMedia) {
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
            let storedTheme = '';
            try {
                storedTheme = localStorage.getItem(THEME_KEY) || '';
            } catch (error) {}
            
            if (!storedTheme) {
                setTheme(e.matches ? 'dark' : 'light');
            }
        });
    }
    
    // Keyboard shortcut (Ctrl/Cmd + Shift + T)
    document.addEventListener('keydown', function(e) {
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 't') {
            e.preventDefault();
            toggleTheme();
        }
    });
    
    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initTheme);
    } else {
        initTheme();
    }
    
    window.MCPTheme = {
        toggle: toggleTheme,
        set: setTheme,
        get: getTheme
    };
    
})();
