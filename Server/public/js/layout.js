// --- public/js/layout.js ---

document.addEventListener("DOMContentLoaded", () => {
    // 1. Create the Navbar
    const navbar = document.createElement('div');
    navbar.className = 'navbar';
    
    // Determine which tab should be highlighted
    const path = window.location.pathname;
    const getActive = (target) => path.includes(target) ? 'active' : '';

    navbar.innerHTML = `
        <div>
            <a href="/dashboard" class="${getActive('/dashboard')}">MiniDM Hub</a>
            <a href="/devices" class="${getActive('/devices')}">Devices</a>
            <a href="/apps" class="${getActive('/apps')}">Software Catalog</a>
            <a href="/policy" class="${getActive('/policy')}">Policy Library</a>
            <a href="/settings" class="${getActive('/settings')}">Settings</a>
        </div>
        <div style="display: flex; align-items: center; gap: 15px;">
            <button id="themeToggle" style="background: none; border: none; font-size: 1.2em; cursor: pointer; padding: 0;" title="Toggle Dark Mode"></button>
            <button class="btn-danger" style="padding: 8px 15px;" onclick="handleLogout()">Logout</button>
        </div>
    `;

    // 2. Insert Navbar at the very top of the body
    document.body.insertBefore(navbar, document.body.firstChild);

    // 3. Theme Toggle Logic
    const themeBtn = document.getElementById('themeToggle');
    
    const updateThemeUI = () => {
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        themeBtn.innerText = isDark ? '☀️' : '🌙';
    };

    updateThemeUI(); // Initial set

    themeBtn.addEventListener('click', () => {
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        const newTheme = isDark ? 'light' : 'dark';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateThemeUI();
    });
});

// 4. Centralized Logout Function
async function handleLogout() {
    const res = await fetch('/api/logout', { method: 'POST' });
    if (res.ok) window.location.href = '/login';
}