// Theme Toggle Functionality
(function() {
  'use strict';

  // Get theme from localStorage or default to dark
  const getTheme = () => {
    const savedTheme = localStorage.getItem('theme');
    return savedTheme || 'dark';
  };

  // Set theme
  const setTheme = (theme) => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    updateThemeIcon(theme);
  };

  // Update theme icon
  const updateThemeIcon = (theme) => {
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
      const icon = themeToggle.querySelector('i');
      if (icon) {
        if (theme === 'light') {
          icon.classList.remove('bi-moon-fill');
          icon.classList.add('bi-sun-fill');
          themeToggle.setAttribute('title', 'Switch to Dark Mode');
        } else {
          icon.classList.remove('bi-sun-fill');
          icon.classList.add('bi-moon-fill');
          themeToggle.setAttribute('title', 'Switch to Light Mode');
        }
      }
    }
  };

  // Toggle theme
  const toggleTheme = () => {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
  };

  // Initialize theme on page load
  const initTheme = () => {
    const theme = getTheme();
    setTheme(theme);
  };

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initTheme);
  } else {
    initTheme();
  }

  // Make toggleTheme available globally
  window.toggleTheme = toggleTheme;
})();

