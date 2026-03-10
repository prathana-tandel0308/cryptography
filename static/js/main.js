document.addEventListener('DOMContentLoaded', () => {
    const body = document.body;
    // Theme toggle removed; keep a fixed dark theme.
    body.setAttribute('data-theme', 'dark');
    localStorage.removeItem('theme');
});
