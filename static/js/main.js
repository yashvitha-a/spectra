/* ===== SPECTRA - Main JavaScript ===== */

// ===== State =====
let currentMode = null;
let currentScenario = null;
let currentStep = 0;
let scenarioSteps = [];
let logs = [];
let sessionId = null;
let companyFiles = [];
let companyName = '';
let allowedCommands = [];
let currentUser = null;
let tutorialStep = 0;
let lucaReadCount = 0;
let scenarioStartTime = null;
let terminalLog = [];
let stepFailCount = 0;
let revealedSteps = 0;

// Cute error mascot reactions
const errorMascots = {
    wrongCmd: [
        { emoji: '🐱', msg: "Hmm, that's not quite right... Try using <strong>help</strong> to see the tool names!" },
        { emoji: '🐰', msg: "Oops! Wrong command for this step. Don't worry, type <strong>help</strong>!" },
        { emoji: '🦊', msg: "Close but no cigar! Check <strong>help</strong> for the right tool keyword." },
        { emoji: '🐻', msg: "That command doesn't match this step. Need a <strong>help</strong>?" },
        { emoji: '😿', msg: "Not the right one! Use <strong>help</strong> to find the correct tool." },
        { emoji: '🙈', msg: "Eek! Try again — <strong>help</strong> will show you the way." },
    ],
    notFound: [
        { emoji: '🐱', msg: "Looked everywhere but can't find that file! Try <strong>ls</strong> to see what's here." },
        { emoji: '🔍', msg: "File not found! Use <strong>ls</strong> to list available files." },
        { emoji: '🐰', msg: "Where did it go? That file doesn't exist. Try <strong>ls</strong>!" },
    ],
    allDone: [
        { emoji: '🎉', msg: "Woohoo! All steps completed! You're a natural!" },
        { emoji: '🐱', msg: "Purr-fect! Everything's done. Time to switch to Detect Mode!" },
        { emoji: '🦊', msg: "All done! Great job, agent. Now go analyze those logs!" },
    ]
};

function getMascotReaction(type) {
    const reactions = errorMascots[type] || errorMascots.wrongCmd;
    const r = reactions[Math.floor(Math.random() * reactions.length)];
    const cssClass = type === 'allDone' ? 'all-done' : type === 'notFound' ? 'not-found' : 'wrong-cmd';
    return `<div class="error-reaction ${cssClass}"><span class="error-mascot">${r.emoji}</span><span class="mascot-text">${r.msg}</span></div>`;
}
let hintsUsed = 0;

// ===== Initialization =====
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initUser();

    document.getElementById('attack-cmd-input')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') handleAttackCommand(e.target.value.trim());
    });
    document.getElementById('detect-cmd-input')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') handleDetectCommand(e.target.value.trim());
    });
    document.getElementById('username-input')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') submitUsername();
    });
});

// ===== User System =====
function initUser() {
    const saved = localStorage.getItem('spectra_user');
    if (saved) {
        currentUser = JSON.parse(saved);
        document.getElementById('username-modal')?.classList.add('hidden');
        updateHomeUserInfo();
    }
}

async function submitUsername() {
    const input = document.getElementById('username-input');
    const username = input.value.trim();
    if (!username) return;
    try {
        const res = await fetch('/api/user/profile', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        currentUser = await res.json();
        localStorage.setItem('spectra_user', JSON.stringify(currentUser));
        document.getElementById('username-modal')?.classList.add('hidden');
        updateHomeUserInfo();
    } catch (e) {
        currentUser = { username, xp: 0, level: 1, completed_scenarios: '[]' };
        localStorage.setItem('spectra_user', JSON.stringify(currentUser));
        document.getElementById('username-modal')?.classList.add('hidden');
        updateHomeUserInfo();
    }
}

function updateHomeUserInfo() {
    if (!currentUser) return;
    const bar = document.getElementById('user-info-bar');
    if (bar) bar.style.display = 'flex';
    const badge = document.getElementById('home-level-badge');
    if (badge) badge.textContent = `LVL ${currentUser.level || 1}`;
    const name = document.getElementById('home-username');
    if (name) name.textContent = currentUser.username;
    const xp = currentUser.xp || 0;
    const progress = (xp % 500) / 500 * 100;
    const fill = document.getElementById('home-xp-fill');
    if (fill) fill.style.width = progress + '%';
    const text = document.getElementById('home-xp-text');
    if (text) text.textContent = xp + ' XP';
}

// ===== Theme Toggle =====
function initTheme() {
    const saved = localStorage.getItem('spectra_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    const btn = document.getElementById('theme-toggle');
    if (btn) btn.textContent = saved === 'dark' ? '🌙' : '☀️';
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('spectra_theme', next);
    const btn = document.getElementById('theme-toggle');
    if (btn) btn.textContent = next === 'dark' ? '🌙' : '☀️';
}

// ===== Settings Panel =====
function toggleSettings() {
    const panel = document.getElementById('settings-panel');
    if (panel) panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
}

// ===== Screen Navigation =====
function showScreen(id) {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    document.getElementById(id)?.classList.add('active');
    toggleSettings(); // close settings if open
    document.getElementById('settings-panel').style.display = 'none';
}

function selectMode(mode) {
    currentMode = mode;
    const title = document.getElementById('scenario-mode-title');
    if (title) title.textContent = mode === 'attack' ? '🔴 Select Attack Scenario' : '🔵 Select Detect Scenario';
    showScreen('scenario-screen');
    loadScenarios();
}

// ===== Scenarios =====
async function loadScenarios() {
    try {
        const res = await fetch('/api/scenarios');
        const scenarios = await res.json();
        const grid = document.getElementById('scenarios-list');
        grid.innerHTML = scenarios.map(s => {
            const rooms = currentMode === 'detect' && s.forensics_rooms ? s.forensics_rooms : (s.tryhackme_rooms || '');
            const roomLinks = rooms.split(';').filter(Boolean).map(r => {
                const [name, url] = r.split('|');
                return url ? `<a href="${url}" target="_blank" class="thm-link">${name}</a>` : '';
            }).join('');
            return `<div class="scenario-card" onclick="selectScenario(${s.id})">
                <h3>${s.name}</h3>
                <p>${s.description}</p>
                <div class="scenario-meta">
                    <span>${s.attack_type}</span>
                    <span>${s.difficulty}</span>
                </div>
                ${roomLinks ? `<div class="thm-rooms"><span class="thm-label">THM:</span>${roomLinks}</div>` : ''}
            </div>`;
        }).join('');
    } catch (e) { console.error('Failed to load scenarios:', e); }
}

async function selectScenario(id) {
    try {
        const [scenarioRes, filesRes] = await Promise.all([
            fetch(`/api/scenario/${id}`),
            fetch(`/api/company-files/${id}`)
        ]);
        currentScenario = await scenarioRes.json();
        const filesData = await filesRes.json();
        companyFiles = filesData.files || [];
        companyName = filesData.company_name || 'Unknown';
        scenarioSteps = currentScenario.steps || [];
        currentStep = 0;
        sessionId = 'session_' + Date.now();
        scenarioStartTime = Date.now();
        hintsUsed = 0;

        allowedCommands = scenarioSteps.map(s => ({
            cmd: s.command, step: s.step_number, action: s.action, hint: s.command_hint
        }));

        if (currentMode === 'attack') {
            showScreen('attack-screen');
            renderAttackMode();
        } else {
            showScreen('detect-screen');
            loadDetectLogs();
        }
    } catch (e) { console.error('Failed to load scenario:', e); }
}

// ===== Attack Mode =====
function renderAttackMode() {
    renderAttackSteps();
    renderCompanyIntel();
    renderAttackChain();
    loadNetworkDiagram();

    const output = document.getElementById('terminal-output');
    output.innerHTML = `<div class="terminal-line system">Welcome to SPECTRA Attack Terminal</div>
        <div class="terminal-line system">Scenario: ${currentScenario.name}</div>
        <div class="terminal-line system">Type <span class="cmd-highlight">help</span> for available commands.</div>`;

    document.getElementById('btn-switch-detect').style.display = 'none';
    document.getElementById('hint-box').style.display = 'none';
    document.getElementById('attack-logs').innerHTML = '<p class="placeholder-text">Execute steps to generate forensic logs...</p>';

    if (scenarioSteps.length > 0) {
        const first = scenarioSteps[0];
        document.getElementById('current-step-title').textContent = `Step 1: ${first.title}`;
        document.getElementById('current-step-description').textContent = first.description;
    }
}

function renderAttackSteps() {
    const panel = document.getElementById('attack-steps');
    panel.innerHTML = scenarioSteps.map((s, i) => `
        <div class="step-item ${i === 0 ? 'active' : ''}" id="step-${i}" onclick="focusStep(${i})">
            <span class="step-number">${s.step_number}</span>
            <span>${s.title}</span>
        </div>
    `).join('');
}

function focusStep(index) {
    document.querySelectorAll('.step-item').forEach(el => el.classList.remove('active'));
    const el = document.getElementById(`step-${index}`);
    if (el && !el.classList.contains('completed')) el.classList.add('active');
    const step = scenarioSteps[index];
    if (step) {
        document.getElementById('current-step-title').textContent = `Step ${step.step_number}: ${step.title}`;
        document.getElementById('current-step-description').textContent = step.description;
    }
}

function renderCompanyIntel() {
    const panel = document.getElementById('company-intel-panel');
    if (!companyFiles.length) { panel.innerHTML = ''; return; }
    panel.innerHTML = `
        <div class="intel-header" onclick="toggleIntelPanel()">
            <strong>🏢 ${companyName} — Intel Files</strong>
            <span class="intel-toggle" id="intel-toggle-icon">▶</span>
        </div>
        <div class="intel-body" id="intel-body" style="display:none;">
            <div class="intel-hint">Use <code>cat &lt;filename&gt;</code> in the terminal to view files.</div>
            ${companyFiles.map(f => `
                <div class="intel-file" onclick="openFileViewer(${f.id})">
                    <span class="file-icon">📄</span>
                    <span class="file-name">${f.filename}</span>
                    <span class="file-path">${f.filepath}</span>
                </div>
            `).join('')}
        </div>`;
}

function toggleIntelPanel() {
    const body = document.getElementById('intel-body');
    const icon = document.getElementById('intel-toggle-icon');
    if (body && icon) {
        const show = body.style.display === 'none';
        body.style.display = show ? 'block' : 'none';
        icon.textContent = show ? '▼' : '▶';
    }
}

// ===== Attack Chain Visualization =====
function renderAttackChain() {
    const panel = document.getElementById('attack-chain-panel');
    if (!scenarioSteps.length) { panel.innerHTML = ''; return; }
    let html = '<div class="attack-chain">';
    scenarioSteps.forEach((s, i) => {
        const state = i < currentStep ? 'completed' : (i === currentStep ? 'active' : '');
        html += `<div class="chain-node">
            <div class="chain-dot ${state}">${i < currentStep ? '✓' : s.step_number}</div>
            <span class="chain-label ${state}">${s.title}</span>
        </div>`;
        if (i < scenarioSteps.length - 1) {
            html += `<span class="chain-arrow ${i < currentStep ? 'completed' : ''}">→</span>`;
        }
    });
    html += '</div>';
    panel.innerHTML = html;
}

// ===== Network Diagram =====
function toggleNetworkDiagram() {
    const body = document.getElementById('nd-body');
    const toggle = document.getElementById('nd-toggle');
    if (body && toggle) {
        const show = body.style.display === 'none';
        body.style.display = show ? 'block' : 'none';
        toggle.textContent = show ? '▼' : '▶';
    }
}

async function loadNetworkDiagram() {
    if (!currentScenario) return;
    try {
        const res = await fetch(`/api/network-map/${currentScenario.id}`);
        const map = await res.json();
        const svg = document.getElementById('network-svg');
        if (!svg) return;

        const typeColors = {
            attacker: '#ff3d5a', server: '#00d9ff', workstation: '#00ff41',
            malicious: '#a855f7', database: '#ffd700', firewall: '#ff8c00',
            router: '#00ffcc', cloud: '#38bdf8'
        };
        const typeIcons = {
            attacker: '💀', server: '🖥️', workstation: '💻',
            malicious: '☠️', database: '🗄️', firewall: '🛡️',
            router: '📡', cloud: '☁️'
        };

        // SVG defs for glow filters
        let html = `<defs>`;
        Object.entries(typeColors).forEach(([type, color]) => {
            html += `<filter id="glow-${type}" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="blur"/>
                <feColorMatrix in="blur" type="matrix" values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 0.6 0"/>
                <feMerge><feMergeNode/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
            <radialGradient id="grad-${type}" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stop-color="${color}" stop-opacity="0.3"/>
                <stop offset="100%" stop-color="${color}" stop-opacity="0"/>
            </radialGradient>`;
        });
        html += `</defs>`;

        // Grid lines for cyber feel
        for (let x = 0; x <= 700; x += 70) {
            html += `<line x1="${x}" y1="0" x2="${x}" y2="400" stroke="rgba(0,217,255,0.04)" stroke-width="0.5"/>`;
        }
        for (let y = 0; y <= 400; y += 50) {
            html += `<line x1="0" y1="${y}" x2="700" y2="${y}" stroke="rgba(0,217,255,0.04)" stroke-width="0.5"/>`;
        }

        // Draw edges with gradient colors
        (map.edges || []).forEach(e => {
            const fromNode = map.nodes.find(n => n.id === e.from);
            const toNode = map.nodes.find(n => n.id === e.to);
            if (fromNode && toNode) {
                const color = typeColors[fromNode.type] || '#1e2a5a';
                html += `<line class="edge-line" x1="${fromNode.x}" y1="${fromNode.y}" x2="${toNode.x}" y2="${toNode.y}" 
                    stroke="${color}" stroke-opacity="0.5"
                    style="animation-delay: ${Math.random() * 2}s"/>`;
                // Arrow at midpoint
                const mx = (fromNode.x + toNode.x) / 2, my = (fromNode.y + toNode.y) / 2;
                const angle = Math.atan2(toNode.y - fromNode.y, toNode.x - fromNode.x) * 180 / Math.PI;
                html += `<polygon points="-5,-4 5,0 -5,4" fill="${color}" opacity="0.6" 
                    transform="translate(${mx},${my}) rotate(${angle})"/>`;
            }
        });

        // Draw nodes with full visual effects
        (map.nodes || []).forEach((n, i) => {
            const type = n.type || 'server';
            const color = typeColors[type] || '#00d9ff';
            const icon = typeIcons[type] || '●';
            const delay = i * 0.4;

            // Outer pulse ring
            html += `<circle class="pulse-ring node-${type}" cx="${n.x}" cy="${n.y}" r="20" 
                fill="none" stroke="${color}" stroke-opacity="0.25" stroke-width="1.5"
                style="animation-delay:${delay}s"/>`;

            // Gradient halo
            html += `<circle cx="${n.x}" cy="${n.y}" r="28" fill="url(#grad-${type})"/>`;

            // Hex border (octagon approximation)
            const r = 22;
            const hexPoints = Array.from({ length: 8 }, (_, k) => {
                const a = (k * Math.PI * 2 / 8) - Math.PI / 8;
                return `${n.x + r * Math.cos(a)},${n.y + r * Math.sin(a)}`;
            }).join(' ');
            html += `<polygon class="node-hex" points="${hexPoints}" 
                fill="${color}" stroke="${color}" stroke-opacity="0.5"/>`;

            // Core circle with glow
            html += `<circle class="node-core node-${type}" cx="${n.x}" cy="${n.y}" r="10" 
                filter="url(#glow-${type})" style="animation-delay:${delay}s"/>`;

            // Emoji icon
            html += `<text x="${n.x}" y="${n.y + 4}" text-anchor="middle" font-size="12" 
                style="text-shadow:none; fill:white; font-family:sans-serif;">${icon}</text>`;

            // Label background
            const labelW = n.label.length * 6 + 10;
            html += `<rect class="node-label-bg" x="${n.x - labelW / 2}" y="${n.y + 26}" 
                width="${labelW}" height="16" rx="4"/>`;
            // Label text
            html += `<text x="${n.x}" y="${n.y + 37}" text-anchor="middle">${n.label}</text>`;
        });

        svg.innerHTML = html;
    } catch (e) { console.error('Failed to load network map:', e); }
}

// ===== File Viewer =====
async function openFileViewer(fileId) {
    try {
        const res = await fetch(`/api/company-file/${fileId}`);
        const file = await res.json();
        document.getElementById('file-modal-filename').textContent = file.filename;
        document.getElementById('file-modal-path').textContent = file.filepath;
        document.getElementById('file-modal-content').textContent = file.content;
        document.getElementById('file-viewer-modal').classList.add('active');
    } catch (e) { console.error('Failed to load file:', e); }
}

function closeFileViewer(event) {
    if (event && event.target !== event.currentTarget && !event.target.classList.contains('file-modal-close')) return;
    document.getElementById('file-viewer-modal').classList.remove('active');
}

function catFile(filename) {
    const file = companyFiles.find(f => f.filename.toLowerCase() === filename.toLowerCase());
    if (file) { openFileViewer(file.id); return true; }
    return false;
}

// ===== Terminal Command Handling (Attack) =====
async function handleAttackCommand(cmd) {
    if (!cmd) return;
    const input = document.getElementById('attack-cmd-input');
    input.value = '';
    const output = document.getElementById('terminal-output');
    output.innerHTML += `<div class="terminal-line user-cmd">${escapeHtml(cmd)}</div>`;
    terminalLog.push({ time: new Date().toISOString(), mode: 'attack', cmd });

    // Basic Linux commands for realism
    const basicCmd = cmd.split(' ')[0].toLowerCase();
    if (['ls', 'dir'].includes(basicCmd)) {
        const files = companyFiles.map(f => f.filename).join('  ');
        output.innerHTML += `<div class="terminal-line output">${files || 'No files in current directory.'}</div>`;
        output.scrollTop = output.scrollHeight; return;
    }
    if (basicCmd === 'pwd') { output.innerHTML += `<div class="terminal-line output">/home/spectra/ops/${currentScenario?.name?.toLowerCase().replace(/\s/g, '-') || 'mission'}</div>`; output.scrollTop = output.scrollHeight; return; }
    if (basicCmd === 'whoami') { output.innerHTML += `<div class="terminal-line output">${currentUser?.username || 'spectra-agent'}</div>`; output.scrollTop = output.scrollHeight; return; }
    if (basicCmd === 'id') { output.innerHTML += `<div class="terminal-line output">uid=1000(${currentUser?.username || 'agent'}) gid=1000(operators) groups=1000(operators),27(sudo)</div>`; output.scrollTop = output.scrollHeight; return; }
    if (basicCmd === 'ifconfig' || basicCmd === 'ip') { output.innerHTML += `<div class="terminal-line output">eth0: 10.0.0.88/24  UP  MTU 1500  HWaddr aa:bb:cc:dd:ee:ff</div><div class="terminal-line output">lo: 127.0.0.1/8  UP  MTU 65536</div>`; output.scrollTop = output.scrollHeight; return; }
    if (basicCmd === 'uname') { output.innerHTML += `<div class="terminal-line output">Linux spectra-kali 6.1.0-kali9 #1 SMP x86_64 GNU/Linux</div>`; output.scrollTop = output.scrollHeight; return; }
    if (basicCmd === 'date') { output.innerHTML += `<div class="terminal-line output">${new Date().toString()}</div>`; output.scrollTop = output.scrollHeight; return; }
    if (basicCmd === 'clear') { output.innerHTML = ''; output.scrollTop = output.scrollHeight; return; }
    if (basicCmd === 'history') {
        const hist = terminalLog.filter(l => l.mode === 'attack').map((l, i) => `<div class="terminal-line output">${i + 1}  ${l.cmd}</div>`).join('');
        output.innerHTML += `<div class="terminal-line info">Command history:</div>${hist}`;
        output.scrollTop = output.scrollHeight; return;
    }
    if (['cd', 'mkdir', 'rm', 'chmod', 'chown', 'touch', 'cp', 'mv', 'echo'].includes(basicCmd)) {
        output.innerHTML += `<div class="terminal-line output">OK</div>`; output.scrollTop = output.scrollHeight; return;
    }

    if (cmd === 'help') {
        const keywords = allowedCommands.map(c => {
            const tool = c.cmd.split(' ')[0];
            return `<div class="terminal-line output">Step ${c.step}: <span class="cmd-highlight">${tool}</span> — ${c.hint}</div>`;
        });
        output.innerHTML += `<div class="terminal-line info">Tool hints (figure out the full command!):</div>${keywords.join('')}`;
        output.innerHTML += `<div class="terminal-line info">Also available: ls, pwd, whoami, id, ifconfig, cat, clear, history</div>`;
        output.innerHTML += `<div class="terminal-line" style="color:var(--yellow);font-size:0.8rem;">💡 Stuck? After 3 wrong tries, type <strong>reveal</strong> or <strong>giveup</strong> to see the answer (−50 XP)</div>`;
        output.scrollTop = output.scrollHeight;
        return;
    }

    if (cmd.startsWith('cat ')) {
        const filename = cmd.substring(4).trim();
        if (!catFile(filename)) {
            output.innerHTML += getMascotReaction('notFound');
        }
        output.scrollTop = output.scrollHeight;
        return;
    }

    const currentAllowed = allowedCommands.find(c => c.step === currentStep + 1);
    if (!currentAllowed) {
        output.innerHTML += getMascotReaction('allDone');
        output.scrollTop = output.scrollHeight;
        return;
    }

    const isCorrect = cmd.trim().toLowerCase() === currentAllowed.cmd.trim().toLowerCase() ||
        cmd.trim() === currentAllowed.cmd.trim();

    if (!isCorrect) {
        stepFailCount++;
        if (cmd.trim().toLowerCase() === 'reveal' || cmd.trim().toLowerCase() === 'giveup') {
            revealedSteps++;
            output.innerHTML += `<div class="error-reaction all-done">
                <span class="error-mascot">📖</span>
                <span class="mascot-text">The command for Step ${currentStep + 1} is:<br><code style="color:var(--green);font-size:1rem;font-weight:700;">${escapeHtml(currentAllowed.cmd)}</code><br><span style="font-size:0.7rem;color:var(--text-dim);">Type it in to continue. (−50 XP penalty for revealing)</span></span>
            </div>`;
            output.scrollTop = output.scrollHeight;
            return;
        }
        if (stepFailCount >= 3) {
            output.innerHTML += `<div class="error-reaction wrong-cmd">
                <span class="error-mascot">😰</span>
                <span class="mascot-text">Struggling? That's <strong>${stepFailCount}</strong> attempts. Type <strong>reveal</strong> or <strong>giveup</strong> to see the full command. (−50 XP penalty)</span>
            </div>`;
        } else {
            output.innerHTML += getMascotReaction('wrongCmd');
        }
        output.scrollTop = output.scrollHeight;
        return;
    }

    // Reset fail count on correct answer
    stepFailCount = 0;

    // Execute step
    const step = scenarioSteps[currentStep];
    output.innerHTML += `<div class="terminal-line success">✓ Executing: ${step.title}...</div>`;
    output.innerHTML += `<div class="terminal-line output">${escapeHtml(step.log_entry)}</div>`;

    // Mark step completed
    const stepEl = document.getElementById(`step-${currentStep}`);
    if (stepEl) { stepEl.classList.remove('active'); stepEl.classList.add('completed'); }

    // Generate log via API
    try {
        await fetch('/api/execute-step', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario_id: currentScenario.id, step_id: step.id, session_id: sessionId })
        });
        await loadAttackLogs();
    } catch (e) { console.error('Error executing step:', e); }

    currentStep++;
    renderAttackChain();

    if (currentStep < scenarioSteps.length) {
        const next = scenarioSteps[currentStep];
        document.getElementById('current-step-title').textContent = `Step ${next.step_number}: ${next.title}`;
        document.getElementById('current-step-description').textContent = next.description;
        document.getElementById(`step-${currentStep}`)?.classList.add('active');
    } else {
        output.innerHTML += `<div class="terminal-line success">═══════════════════════════════════</div>`;
        output.innerHTML += `<div class="terminal-line success">✓ All attack steps completed!</div>`;
        output.innerHTML += `<div class="terminal-line info">Switch to Detect Mode to analyze the forensic evidence.</div>`;
        document.getElementById('btn-switch-detect').style.display = 'inline-block';
        document.getElementById('current-step-title').textContent = '✅ Attack Complete';
        document.getElementById('current-step-description').textContent = 'All steps executed. Switch to Detect Mode to investigate.';

        await awardXP(currentScenario.id);
    }
    output.scrollTop = output.scrollHeight;
}

async function loadAttackLogs() {
    try {
        const res = await fetch(`/api/session-logs/${sessionId}`);
        const data = await res.json();
        const container = document.getElementById('attack-logs');
        container.innerHTML = data.map(log => `
            <div class="log-entry">
                <span class="log-type log-type-${log.log_type}">${log.log_type}</span>
                <div class="log-time">${log.timestamp}</div>
                <div class="log-content">${escapeHtml(log.content)}</div>
            </div>
        `).join('');
    } catch (e) { console.error('Error loading logs:', e); }
}

// ===== XP & Achievements =====
async function awardXP(scenarioId) {
    if (!currentUser) return;
    const difficulty = currentScenario?.difficulty || 'Beginner';
    const xpMap = { 'Beginner': 100, 'Intermediate': 200, 'Advanced': 300 };
    const xp = xpMap[difficulty] || 100;

    try {
        const res = await fetch('/api/user/xp', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: currentUser.username, xp, scenario_id: scenarioId })
        });
        const data = await res.json();
        currentUser.xp = data.xp;
        currentUser.level = data.level;
        currentUser.completed_scenarios = JSON.stringify(data.completed_scenarios);
        localStorage.setItem('spectra_user', JSON.stringify(currentUser));
        updateHomeUserInfo();

        // Show XP award on results
        const xpDisplay = document.getElementById('xp-award-display');
        if (xpDisplay) {
            xpDisplay.style.display = 'block';
            document.getElementById('xp-award-text').textContent = `+${xp} XP earned! Level ${data.level} — ${data.level_name}`;
        }

        if (data.leveled_up) {
            showAchievementPopup('🏆', `Level Up! You are now ${data.level_name}`);
        }

        // Check achievements
        checkAchievements(scenarioId, data);
    } catch (e) { console.error('Error awarding XP:', e); }
}

async function checkAchievements(scenarioId, xpData) {
    if (!currentUser) return;
    const completed = xpData?.completed_scenarios || [];

    // First Blood
    if (completed.length === 1) await unlockAchievement('first_blood');

    // Speed Demon
    if (scenarioStartTime && (Date.now() - scenarioStartTime) < 300000) {
        await unlockAchievement('speed_demon');
    }

    // Malware Hunter
    if (scenarioId === 3) await unlockAchievement('malware_hunter');

    // Red Master (all 8 scenarios)
    if (completed.length >= 8) await unlockAchievement('red_master');

    // Elite Hacker
    if ((currentUser.level || 1) >= 5) await unlockAchievement('elite_hacker');

    // Shadow Analyst
    if (hintsUsed === 0 && currentStep >= scenarioSteps.length) {
        await unlockAchievement('shadow_analyst');
    }
}

async function unlockAchievement(key) {
    if (!currentUser) return;
    try {
        const res = await fetch('/api/achievements/unlock', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: currentUser.username, achievement_key: key })
        });
        const data = await res.json();
        if (data.unlocked) {
            const achNames = {
                first_blood: { icon: '🩸', name: 'First Blood' },
                speed_demon: { icon: '⚡', name: 'Speed Demon' },
                perfect_analyst: { icon: '🎯', name: 'Perfect Analyst' },
                red_master: { icon: '🔴', name: 'Red Master' },
                blue_master: { icon: '🔵', name: 'Blue Master' },
                knowledge_seeker: { icon: '📚', name: 'Knowledge Seeker' },
                elite_hacker: { icon: '🏆', name: 'Elite Hacker' },
                shadow_analyst: { icon: '🕵️', name: 'Shadow Analyst' },
                malware_hunter: { icon: '💀', name: 'Malware Hunter' },
                defender: { icon: '🛡️', name: 'Defender' },
                team_player: { icon: '👥', name: 'Team Player' },
                duelist: { icon: '⚔️', name: 'Duelist' }
            };
            const ach = achNames[key] || { icon: '🏅', name: key };
            showAchievementPopup(ach.icon, ach.name);
        }
    } catch (e) { console.error('Error unlocking achievement:', e); }
}

function showAchievementPopup(icon, name) {
    const popup = document.getElementById('achievement-popup');
    document.getElementById('ach-popup-icon').textContent = icon;
    document.getElementById('ach-popup-name').textContent = name;
    popup.style.display = 'flex';
    setTimeout(() => { popup.style.display = 'none'; }, 4000);
}

// ===== Detect Mode =====
function switchToDetect() {
    currentMode = 'detect';
    showScreen('detect-screen');
    loadDetectLogs();
}

async function loadDetectLogs() {
    try {
        // Use noise endpoint for extra challenge
        const url = sessionId ? `/api/session-logs-with-noise/${sessionId}` : `/api/session-logs/${sessionId}`;
        const res = await fetch(url);
        logs = await res.json();
        renderDetectLogs(logs);
        renderTimeline(logs);
    } catch (e) {
        console.error('Error loading detect logs:', e);
        document.getElementById('detect-logs').innerHTML = '<p class="placeholder-text">No logs available. Complete attack mode first.</p>';
    }
}

function renderDetectLogs(logsList) {
    const container = document.getElementById('detect-logs');
    container.innerHTML = logsList.map(log => {
        const isNoise = log.is_evidence === 0;
        return `<div class="log-entry ${isNoise ? 'noise-log' : ''}">
            <span class="log-type log-type-${log.log_type}">${log.log_type}</span>
            <div class="log-time">${log.timestamp}</div>
            <div class="log-content">${escapeHtml(log.content)}</div>
        </div>`;
    }).join('');
}

function renderTimeline(logsList) {
    const container = document.getElementById('evidence-timeline');
    const evidenceLogs = logsList.filter(l => l.is_evidence !== 0);
    container.innerHTML = evidenceLogs.map(log => `
        <div class="timeline-entry">
            <span class="tl-time">${log.timestamp?.split('T')[1]?.substring(0, 5) || '--:--'}</span>
            <span class="tl-content">${escapeHtml(log.content?.substring(0, 80))}...</span>
        </div>
    `).join('');
}

// ===== Terminal Command Handling (Detect) =====
function handleDetectCommand(cmd) {
    if (!cmd) return;
    const input = document.getElementById('detect-cmd-input');
    input.value = '';
    const output = document.getElementById('detect-terminal-output');
    output.innerHTML += `<div class="terminal-line user-cmd">${escapeHtml(cmd)}</div>`;
    terminalLog.push({ time: new Date().toISOString(), mode: 'detect', cmd });

    const parts = cmd.split(' ');
    const command = parts[0].toLowerCase();
    const args = parts.slice(1).join(' ');

    // Basic Linux commands in detect mode too
    if (command === 'clear') { output.innerHTML = ''; output.scrollTop = output.scrollHeight; return; }
    if (command === 'history') {
        const hist = terminalLog.filter(l => l.mode === 'detect').map((l, i) => `<div class="terminal-line output">${i + 1}  ${l.cmd}</div>`).join('');
        output.innerHTML += `<div class="terminal-line info">Command history:</div>${hist}`;
        output.scrollTop = output.scrollHeight; return;
    }
    if (['pwd', 'whoami', 'id', 'ls', 'date'].includes(command)) {
        const responses = { pwd: '/home/spectra/forensics', whoami: currentUser?.username || 'forensics-analyst', id: 'uid=1000(analyst) gid=1000(blue-team)', ls: 'evidence.log  timeline.dat  case_notes.txt', date: new Date().toString() };
        output.innerHTML += `<div class="terminal-line output">${responses[command]}</div>`;
        output.scrollTop = output.scrollHeight; return;
    }

    switch (command) {
        case 'help':
            output.innerHTML += `<div class="terminal-line info">Available forensics commands:</div>
                <div class="terminal-line output"><span class="cmd-highlight">grep &lt;term&gt;</span> — Search logs for a keyword</div>
                <div class="terminal-line output"><span class="cmd-highlight">timeline</span> — Show event timeline</div>
                <div class="terminal-line output"><span class="cmd-highlight">filter &lt;type&gt;</span> — Filter by log type</div>
                <div class="terminal-line output"><span class="cmd-highlight">analyze</span> — Analyze current logs</div>
                <div class="terminal-line output"><span class="cmd-highlight">logs</span> — Show all logs</div>
                <div class="terminal-line output"><span class="cmd-highlight">count</span> — Count logs by type</div>
                <div class="terminal-line output"><span class="cmd-highlight">noise</span> — Identify potential noise logs</div>`;
            break;

        case 'grep':
            if (!args) { output.innerHTML += `<div class="terminal-line error">Usage: grep &lt;search term&gt;</div>`; break; }
            const matches = logs.filter(l => l.content.toLowerCase().includes(args.toLowerCase()));
            if (matches.length === 0) {
                output.innerHTML += `<div class="terminal-line output">No matches for "${escapeHtml(args)}"</div>`;
            } else {
                output.innerHTML += `<div class="terminal-line success">${matches.length} match(es) found:</div>`;
                matches.forEach(m => {
                    output.innerHTML += `<div class="terminal-line output">[${m.timestamp}] ${escapeHtml(m.content.substring(0, 100))}</div>`;
                });
            }
            break;

        case 'timeline':
            const sorted = [...logs].filter(l => l.is_evidence !== 0).sort((a, b) => a.timestamp.localeCompare(b.timestamp));
            output.innerHTML += `<div class="terminal-line info">Evidence Timeline (${sorted.length} events):</div>`;
            sorted.forEach(l => {
                output.innerHTML += `<div class="terminal-line output">[${l.timestamp}] ${escapeHtml(l.content.substring(0, 80))}</div>`;
            });
            break;

        case 'filter':
            if (!args) { output.innerHTML += `<div class="terminal-line error">Usage: filter &lt;log_type&gt;</div>`; break; }
            const filtered = logs.filter(l => l.log_type.toLowerCase().includes(args.toLowerCase()));
            output.innerHTML += `<div class="terminal-line info">${filtered.length} logs of type "${escapeHtml(args)}":</div>`;
            filtered.forEach(l => {
                output.innerHTML += `<div class="terminal-line output">[${l.log_type}] ${escapeHtml(l.content.substring(0, 80))}</div>`;
            });
            break;

        case 'analyze':
            output.innerHTML += `<div class="terminal-line info">Analysis Summary:</div>`;
            output.innerHTML += `<div class="terminal-line output">Total logs: ${logs.length}</div>`;
            const noise = logs.filter(l => l.is_evidence === 0).length;
            const evidence = logs.length - noise;
            output.innerHTML += `<div class="terminal-line output">Evidence logs: ${evidence}</div>`;
            output.innerHTML += `<div class="terminal-line output">Noise logs: ${noise}</div>`;
            const types = {};
            logs.forEach(l => { types[l.log_type] = (types[l.log_type] || 0) + 1; });
            Object.entries(types).forEach(([t, c]) => {
                output.innerHTML += `<div class="terminal-line output">  ${t}: ${c}</div>`;
            });
            break;

        case 'logs':
            logs.forEach(l => {
                output.innerHTML += `<div class="terminal-line output">[${l.log_type}] [${l.timestamp}] ${escapeHtml(l.content.substring(0, 100))}</div>`;
            });
            break;

        case 'count':
            const counts = {};
            logs.forEach(l => { counts[l.log_type] = (counts[l.log_type] || 0) + 1; });
            output.innerHTML += `<div class="terminal-line info">Log counts:</div>`;
            Object.entries(counts).forEach(([t, c]) => {
                output.innerHTML += `<div class="terminal-line output">${t}: ${c}</div>`;
            });
            break;

        case 'noise':
            const noiseLogs = logs.filter(l => l.is_evidence === 0);
            output.innerHTML += `<div class="terminal-line info">${noiseLogs.length} potential noise logs detected:</div>`;
            noiseLogs.forEach(l => {
                output.innerHTML += `<div class="terminal-line output" style="opacity:0.6">[NOISE] ${escapeHtml(l.content.substring(0, 80))}</div>`;
            });
            break;

        default:
            output.innerHTML += `<div class="terminal-line error">Unknown command: ${escapeHtml(command)}. Type <span class="cmd-highlight">help</span> for commands.</div>`;
    }
    output.scrollTop = output.scrollHeight;
}

// ===== Analysis Submission =====
async function submitAnalysis() {
    const analysis = document.getElementById('analysis-text').value;
    const findings = [...document.querySelectorAll('#findings-checklist input:checked')].map(c => c.value);

    if (!analysis.trim() && findings.length === 0) {
        alert('Please write your analysis and check relevant findings.');
        return;
    }

    try {
        const res = await fetch('/api/analyze', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId, analysis, findings, scenario_id: currentScenario?.id })
        });
        const result = await res.json();
        showResults(result);
    } catch (e) {
        console.error('Error submitting analysis:', e);
        showResults({ score: 0, correct_findings: {}, message: 'Error submitting analysis' });
    }
}

// Real-world case studies mapped to scenarios
const caseStudies = {
    1: { title: '2020 Twitter Spear Phishing', desc: 'Attackers socially engineered Twitter employees via phone phishing to gain access to internal tools. They hijacked 130+ high-profile accounts (Obama, Musk, Apple) to promote a Bitcoin scam, stealing $120K.', steps: ['Step 1 (Recon): Attackers researched Twitter employees on LinkedIn', 'Step 2 (Phishing email): Sent via phone — vishing attack on IT support', 'Step 3 (Credential capture): Gained VPN credentials for internal tools', 'Step 4 (Lateral access): Used admin panel to take over verified accounts'] },
    2: { title: '2017 Equifax SQL Injection (CVE-2017-5638)', desc: 'Attackers exploited an Apache Struts vulnerability on Equifax servers. They accessed databases containing 147 million SSNs, birth dates, and credit data. Equifax paid $700M in settlements.', steps: ['Step 1-3 (Injection): Exploited input validation flaw in web framework', 'Step 4-5 (Data extraction): Queried credit history and PII tables', 'Step 6 (Exfiltration): Encrypted data exfiltrated over 76 days unnoticed'] },
    3: { title: '2017 WannaCry Ransomware', desc: 'WannaCry spread via EternalBlue (SMB exploit leaked from NSA). It encrypted files on 200,000+ machines across 150 countries. NHS hospitals, FedEx, and Telefonica were severely impacted.', steps: ['Step 1-2 (Payload + delivery): EternalBlue exploit auto-propagated via port 445', 'Step 3-4 (Execution + spread): Self-replicating worm encrypted files on each machine', 'Step 5-6 (Encrypt + ransom): AES-256 encryption with $300 BTC ransom per machine'] },
    4: { title: '2020 SolarWinds Insider/Supply Chain', desc: 'Though primarily a supply chain attack, the SolarWinds breach involved insider-level access. Attackers inserted SUNBURST malware into Orion updates, affecting 18,000 organizations including US government agencies.', steps: ['Step 1-2 (Access + extraction): Attackers had code-level access for months', 'Step 3-4 (Exfiltration): Data sent to attacker-controlled cloud infrastructure', 'Step 5-6 (Cover tracks): Mimicked legitimate SolarWinds traffic patterns'] },
    5: { title: '2016 Dyn DDoS (Mirai Botnet)', desc: 'The Mirai botnet harnessed 600,000 IoT devices (cameras, DVRs) to flood Dyn DNS with 1.2 Tbps. Twitter, Netflix, Reddit, and GitHub went down for hours across the US East Coast.', steps: ['Step 1-2 (Recon + botnet): Mirai scanned for IoT devices with default passwords', 'Step 3-4 (SYN + HTTP flood): Multi-vector attack saturated Dyn infrastructure', 'Step 5-6 (Amplification): DNS amplification multiplied attack traffic 50x'] },
    6: { title: '2015 Darkhotel APT (MITM)', desc: 'Darkhotel APT targeted executives at luxury hotels by compromising hotel WiFi. They used ARP spoofing and SSL stripping to intercept credentials and install keyloggers on business travelers laptops.', steps: ['Step 1-2 (Network + ARP): Compromised hotel WiFi routers for ARP spoofing', 'Step 3-5 (Capture + strip): Intercepted HTTPS traffic and harvested credentials', 'Step 6 (Session hijack): Used stolen sessions to access corporate email'] },
    7: { title: '2019 Sea Turtle DNS Hijacking', desc: 'Sea Turtle (state-sponsored) targeted DNS registries and registrars across the Middle East. They modified DNS records to redirect traffic through attacker-controlled servers, intercepting credentials for government agencies.', steps: ['Step 1-3 (DNS compromise): Gained access to DNS registrars and poisoned records', 'Step 4-5 (Clone + harvest): Man-in-the-middle via cloned sites with valid SSL certs', 'Step 6 (Exploitation): Used stolen credentials for long-term espionage access'] },
    8: { title: '2021 ua-parser-js NPM Supply Chain Attack', desc: 'The ua-parser-js package (7M weekly downloads) was hijacked via a compromised maintainer account. Attackers published versions containing cryptominers and password stealers, affecting thousands of projects.', steps: ['Step 1-2 (Target + compromise): Maintainer account lacked MFA protection', 'Step 3-4 (Inject + publish): Malicious postinstall script added to the package', 'Step 5-6 (Collect + pivot): Cryptominer + credential stealer deployed on install'] }
};

function showResults(result) {
    showScreen('results-screen');
    const score = Math.round(result.score || 0);
    const scoreCircle = document.getElementById('score-circle');
    const scoreValue = document.getElementById('score-value');
    const scoreMessage = document.getElementById('score-message');

    scoreValue.textContent = score;
    scoreMessage.textContent = result.message || 'Analysis complete.';

    scoreCircle.classList.remove('high', 'medium', 'low');
    if (score >= 75) scoreCircle.classList.add('high');
    else if (score >= 40) scoreCircle.classList.add('medium');
    else scoreCircle.classList.add('low');

    // Display findings
    const findingsContainer = document.getElementById('findings-results');
    const findings = result.correct_findings || {};
    findingsContainer.innerHTML = Object.entries(findings).map(([key, found]) => `
        <div class="finding-result ${found ? 'found' : 'missed'}">
            <span class="icon">${found ? '✅' : '❌'}</span>
            <span class="label">${key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</span>
        </div>
    `).join('');

    // Real-world case study
    const caseStudy = caseStudies[currentScenario?.id];
    if (caseStudy) {
        const caseEl = document.getElementById('case-study-section');
        if (caseEl) {
            caseEl.style.display = 'block';
            caseEl.innerHTML = `<h3 class="section-title">📰 Real-World Case Study</h3>
                <div class="case-study-card">
                    <h4>${escapeHtml(caseStudy.title)}</h4>
                    <p>${escapeHtml(caseStudy.desc)}</p>
                    <div class="case-steps">
                        <h5>How This Scenario Maps to the Real Attack:</h5>
                        ${caseStudy.steps.map(s => `<div class="case-step">→ ${escapeHtml(s)}</div>`).join('')}
                    </div>
                </div>`;
        }
    }

    // XP for detect mode
    if (score > 0 && currentScenario) {
        awardXP(currentScenario.id);
    }

    // Check perfect analyst
    if (score === 100) unlockAchievement('perfect_analyst');
}

function retryDetect() {
    if (sessionId) {
        showScreen('detect-screen');
        loadDetectLogs();
    } else {
        showScreen('home-screen');
    }
}

// ===== Hints =====
function requestHint(mode) {
    hintsUsed++;
    if (mode === 'attack') {
        const step = scenarioSteps[currentStep];
        if (!step) return;
        document.getElementById('hint-box').style.display = 'block';
        document.getElementById('hint-text').textContent = step.command_hint || 'No hint available.';
    } else {
        const output = document.getElementById('detect-terminal-output');
        const hints = [
            'Try using grep to search for suspicious keywords like "phishing", "ssh", or "credential".',
            'Check the timeline for events happening outside business hours.',
            'Use the analyze command to get an overview of log types.',
            'Look for entries with unusual IP addresses or domains.',
            'Use the noise command to identify benign logs you can ignore.'
        ];
        const hint = hints[Math.floor(Math.random() * hints.length)];
        output.innerHTML += `<div class="terminal-line info">💡 ${hint}</div>`;
        output.scrollTop = output.scrollHeight;
    }
}

// ===== Tool Info Database (for visual cards) =====
const toolInfo = {
    'nmap': { icon: '🔍', name: 'NMAP', cat: 'Recon', desc: 'Network Mapper — the essential port scanner. Discovers hosts, open ports, services, and OS info on target networks.', syntax: 'nmap [flags] <target>', flags: { '-sS': 'SYN stealth scan (half-open)', '-sV': 'Detect service versions', '-sC': 'Run default scripts', '-p': 'Specify port(s)', '-O': 'OS detection', '-A': 'Aggressive scan (OS + scripts + traceroute)' } },
    'setoolkit': { icon: '🎣', name: 'SET', cat: 'Social Eng', desc: 'Social Engineering Toolkit — automates phishing, credential harvesting, and social engineering attacks.', syntax: 'setoolkit --phish --template <name>', flags: { '--phish': 'Launch phishing module', '--template': 'Email template to use', '--clone': 'Clone a website for harvesting' } },
    'httrack': { icon: '📋', name: 'HTTRACK', cat: 'Cloning', desc: 'Website mirroring tool. Creates offline copies of entire websites — often used to build fake login portals.', syntax: 'httrack --clone <url>', flags: { '--clone': 'Full site clone', '--mirror': 'Recursive mirror', '-O': 'Output directory' } },
    'sendmail': { icon: '✉️', name: 'SENDMAIL', cat: 'Delivery', desc: 'Email delivery utility. Sends emails with custom headers — used for spoofed email delivery in phishing.', syntax: 'sendmail --to <email> --spoof <addr>', flags: { '--to': 'Recipient address', '--spoof': 'Spoofed sender', '--subject': 'Email subject' } },
    'harvest': { icon: '🪤', name: 'HARVEST', cat: 'Capture', desc: 'Credential harvesting listener. Captures usernames and passwords submitted to fake login forms.', syntax: 'harvest --listen <port> --capture <type>', flags: { '--listen': 'Port to listen on', '--capture': 'Data type to capture', '--log': 'Log file path' } },
    'ssh': { icon: '🔐', name: 'SSH', cat: 'Access', desc: 'Secure Shell — encrypted remote login. Used for lateral movement with stolen credentials.', syntax: 'ssh user@host -i <key>', flags: { '-i': 'Identity/key file', '-p': 'Port number', '-L': 'Local port forward', '-D': 'Dynamic SOCKS proxy' } },
    'dirb': { icon: '📂', name: 'DIRB', cat: 'Recon', desc: 'Web directory brute-forcer. Discovers hidden files and folders on web servers using wordlists.', syntax: 'dirb <url> <wordlist>', flags: { '-a': 'Custom User-Agent', '-o': 'Output file', '-r': 'Non-recursive' } },
    'sqlmap': { icon: '💉', name: 'SQLMAP', cat: 'Injection', desc: 'Automated SQL injection tool. Detects and exploits SQLi vulnerabilities to dump databases.', syntax: 'sqlmap -u <url> --dbs', flags: { '-u': 'Target URL with param', '--dbs': 'List databases', '--dump': 'Dump table data', '--batch': 'Non-interactive mode', '--level': 'Test level (1-5)' } },
    'msfvenom': { icon: '🧬', name: 'MSFVENOM', cat: 'Payload', desc: 'Metasploit payload generator. Creates malware payloads for various platforms and encodings.', syntax: 'msfvenom -p <payload> LHOST=<ip>', flags: { '-p': 'Payload type', 'LHOST': 'Listener IP address', 'LPORT': 'Listener port', '-f': 'Output format', '-e': 'Encoder to use' } },
    'nc': { icon: '🔌', name: 'NETCAT', cat: 'Network', desc: 'The TCP/UDP Swiss Army knife. Reads/writes data across network connections — reverse shells, file transfers.', syntax: 'nc -lvp <port>', flags: { '-l': 'Listen mode', '-v': 'Verbose output', '-p': 'Port number', '-e': 'Execute command on connect' } },
    'scp': { icon: '📤', name: 'SCP', cat: 'Exfil', desc: 'Secure Copy over SSH. Transfers files between hosts over encrypted connections.', syntax: 'scp <file> user@host:<path>', flags: { '-r': 'Recursive (directories)', '-P': 'Port number', '-i': 'Identity key file' } },
    'hping3': { icon: '🌊', name: 'HPING3', cat: 'Flood', desc: 'Packet crafting & flood tool. Sends custom TCP/UDP/ICMP packets for DDoS and firewall testing.', syntax: 'hping3 -S --flood -p <port> <target>', flags: { '-S': 'SYN flag', '--flood': 'Max speed', '-p': 'Destination port', '-a': 'Spoofed source IP', '--rand-source': 'Random source IPs' } },
    'slowloris': { icon: '🐌', name: 'SLOWLORIS', cat: 'DoS', desc: 'HTTP slow-attack tool. Holds connections open with partial headers, exhausting server resources.', syntax: 'slowloris -t <target> -s <sockets>', flags: { '-t': 'Target hostname', '-s': 'Number of sockets', '-p': 'Port (default 80)' } },
    'botnet': { icon: '🤖', name: 'BOTNET', cat: 'C2', desc: 'Command & Control tool. Activates and coordinates distributed bot nodes for attacks.', syntax: 'botnet --activate --nodes <n>', flags: { '--activate': 'Bring nodes online', '--nodes': 'Number of bots', '--region': 'Geographic distribution', '--target': 'Attack target' } },
    'arpspoof': { icon: '🕸️', name: 'ARPSPOOF', cat: 'MITM', desc: 'ARP cache poisoning tool. Redirects LAN traffic through attacker machine for interception.', syntax: 'arpspoof -i <iface> -t <target> <gateway>', flags: { '-i': 'Network interface', '-t': 'Target IP', '-r': 'Bidirectional poisoning' } },
    'ettercap': { icon: '👁️', name: 'ETTERCAP', cat: 'Sniffer', desc: 'Comprehensive MITM suite. Captures passwords, injects packets, and performs network analysis.', syntax: 'ettercap -T -q -M arp:remote', flags: { '-T': 'Text mode', '-q': 'Quiet mode', '-M': 'MITM method', '-i': 'Interface' } },
    'sslstrip': { icon: '🔓', name: 'SSLSTRIP', cat: 'Downgrade', desc: 'HTTPS downgrade attack. Strips SSL/TLS from connections, forcing plaintext HTTP for interception.', syntax: 'sslstrip -l <port>', flags: { '-l': 'Listen port', '-a': 'Log all traffic', '-f': 'Favicon spoofing' } },
    'tcpdump': { icon: '📡', name: 'TCPDUMP', cat: 'Capture', desc: 'Network packet capture tool. Records raw packets for offline analysis in Wireshark.', syntax: 'tcpdump -i <iface> -w <file>', flags: { '-i': 'Interface to capture', '-w': 'Write to pcap file', '-c': 'Packet count limit', '-n': 'No DNS resolution' } },
    'ferret': { icon: '🦊', name: 'FERRET', cat: 'Extract', desc: 'Session token extractor. Parses captured traffic to find session cookies and auth tokens.', syntax: 'ferret -i <capture.pcap>', flags: { '-i': 'Input capture file', '-o': 'Output tokens file' } },
    'hamster': { icon: '🐹', name: 'HAMSTER', cat: 'Hijack', desc: 'Session sidejacking proxy. Uses stolen cookies to hijack authenticated sessions.', syntax: 'hamster -s <session_file>', flags: { '-s': 'Session token file', '-p': 'Proxy port' } },
    'dig': { icon: '⛏️', name: 'DIG', cat: 'DNS', desc: 'DNS lookup utility. Queries DNS servers for records — zone transfers reveal entire domain maps.', syntax: 'dig axfr @<dns> <domain>', flags: { 'axfr': 'Zone transfer request', '@': 'DNS server to query', '+short': 'Brief output', '+trace': 'Trace resolution path' } },
    'dnschef': { icon: '👨‍🍳', name: 'DNSCHEF', cat: 'Spoof', desc: 'DNS proxy for forging responses. Redirects domain lookups to attacker-controlled IPs.', syntax: 'dnschef --fakeip <ip> --fakedomains <dom>', flags: { '--fakeip': 'Spoofed IP address', '--fakedomains': 'Domains to spoof', '-i': 'Interface', '-p': 'Port' } },
    'curl': { icon: '🌐', name: 'CURL', cat: 'HTTP', desc: 'Command-line HTTP client. Sends requests with custom headers, cookies, and POST data.', syntax: 'curl -b <cookies> --data <payload> <url>', flags: { '-b': 'Send cookies', '--data': 'POST body', '-H': 'Custom header', '-X': 'HTTP method', '-o': 'Output file' } },
    'npm': { icon: '📦', name: 'NPM', cat: 'Supply Chain', desc: 'Node.js package manager. Attackers publish trojanized packages to infect developer machines.', syntax: 'npm publish --tag <version>', flags: { 'publish': 'Push to registry', '--tag': 'Version tag', 'install': 'Install a package' } },
    'pg_dump': { icon: '🗄️', name: 'PG_DUMP', cat: 'Exfil', desc: 'PostgreSQL database export. Dumps entire database contents to a file for exfiltration.', syntax: 'pg_dump -h <host> -U <user> <db>', flags: { '-h': 'Database host', '-U': 'Username', '-f': 'Output file', '-t': 'Specific table' } },
    'credential-spray': { icon: '🔑', name: 'CRED-SPRAY', cat: 'Brute Force', desc: 'Password spraying tool. Tests common passwords against multiple accounts to avoid lockouts.', syntax: 'credential-spray --target <url> --wordlist <file>', flags: { '--target': 'Login endpoint', '--wordlist': 'Password list', '--users': 'Usernames file' } },
    'arp-scan': { icon: '📡', name: 'ARP-SCAN', cat: 'Recon', desc: 'ARP scanning tool. Discovers all hosts on a local network segment by sending ARP requests.', syntax: 'arp-scan --localnet -I <iface>', flags: { '--localnet': 'Scan local network', '-I': 'Interface to use', '--retry': 'Retry count' } },
    'beef-xss': { icon: '🥩', name: 'BeEF-XSS', cat: 'Exploit', desc: 'Browser Exploitation Framework. Hooks victim browsers and launches client-side attacks via XSS.', syntax: 'beef-xss --hook <url>', flags: { '--hook': 'Inject hook script', '--target': 'Target URL', '--modules': 'Load attack modules' } },
    'ddos-manager': { icon: '💥', name: 'DDOS-MGR', cat: 'Flood', desc: 'DDoS orchestration tool. Manages and coordinates distributed denial-of-service attack traffic.', syntax: 'ddos-manager --target <ip> --method <type>', flags: { '--target': 'Target IP/domain', '--method': 'Attack method', '--duration': 'Attack duration', '--threads': 'Thread count' } },
    'dnsamplify': { icon: '📢', name: 'DNS-AMP', cat: 'DDoS', desc: 'DNS amplification attack tool. Exploits open DNS resolvers to multiply attack traffic volume.', syntax: 'dnsamplify --resolvers <list> --target <ip>', flags: { '--resolvers': 'Open DNS resolvers list', '--target': 'Victim IP', '--rate': 'Packets per second' } },
    'dnspoisoner': { icon: '☠️', name: 'DNSPOISONER', cat: 'DNS', desc: 'DNS cache poisoning tool. Injects forged DNS responses to redirect traffic to attacker-controlled servers.', syntax: 'dnspoisoner --target-resolver <ip> --domain <dom> --ip <fake>', flags: { '--target-resolver': 'DNS server to poison', '--domain': 'Domain to spoof', '--ip': 'Redirect IP address' } },
    'hashcat': { icon: '🔓', name: 'HASHCAT', cat: 'Cracking', desc: 'Advanced password recovery tool. Cracks hashed passwords using GPU acceleration and multiple attack modes.', syntax: 'hashcat -m <mode> -a 0 <hashes> <wordlist>', flags: { '-m': 'Hash type (mode)', '-a': 'Attack type', '-o': 'Output file', '--force': 'Ignore warnings' } },
    'meterpreter>': { icon: '🎯', name: 'METERPRETER', cat: 'Post-Exploit', desc: 'Metasploit post-exploitation shell. Provides remote control, file access, and privilege escalation on compromised systems.', syntax: 'meterpreter> <command>', flags: { 'upload': 'Upload file to target', 'download': 'Download from target', 'hashdump': 'Dump password hashes', 'getsystem': 'Escalate to SYSTEM' } },
    'msfconsole': { icon: '💀', name: 'MSFCONSOLE', cat: 'Exploit', desc: 'Metasploit Framework console. The primary interface for launching exploits and managing attack sessions.', syntax: 'msfconsole -x "use <exploit>"', flags: { 'use': 'Select exploit module', 'set': 'Set option value', 'exploit': 'Launch the attack', 'sessions': 'List active sessions' } },
    'psql': { icon: '🗃️', name: 'PSQL', cat: 'Database', desc: 'PostgreSQL interactive terminal. Connects to databases for direct SQL querying and data extraction.', syntax: 'psql -h <host> -U <user> -d <db>', flags: { '-h': 'Database host', '-U': 'Username', '-d': 'Database name', '-c': 'Run SQL command' } },
    'ransomware': { icon: '🔒', name: 'RANSOMWARE', cat: 'Malware', desc: 'Ransomware deployment tool. Encrypts target files and drops ransom notes demanding payment.', syntax: 'ransomware --encrypt --target <dir>', flags: { '--encrypt': 'Start encryption', '--target': 'Target directory', '--key': 'Encryption key', '--note': 'Ransom note file' } },
    'shred': { icon: '🗑️', name: 'SHRED', cat: 'Anti-Forensics', desc: 'Secure file deletion. Overwrites files multiple times to prevent forensic recovery of evidence.', syntax: 'shred -vfz -n 5 <file>', flags: { '-v': 'Verbose output', '-f': 'Force permissions', '-z': 'Final zero pass', '-n': 'Number of overwrite passes' } },
    'tor-browser': { icon: '🧅', name: 'TOR', cat: 'Anonymity', desc: 'Tor network browser. Routes traffic through multiple relays to hide attacker identity and location.', syntax: 'tor-browser --connect', flags: { '--connect': 'Establish Tor circuit', '--exit': 'Specify exit node', '--bridge': 'Use bridge relay' } },
    'vpn': { icon: '🛡️', name: 'VPN', cat: 'Anonymity', desc: 'Virtual Private Network. Encrypts traffic and masks IP address for anonymous operations.', syntax: 'vpn --connect <server>', flags: { '--connect': 'Connect to server', '--kill-switch': 'Block non-VPN traffic', '--protocol': 'VPN protocol (WireGuard/OpenVPN)' } },
};

function getToolCard(toolName, step) {
    const tool = toolInfo[toolName];
    if (!tool) {
        return `<div class="cmd-card">
            <div class="cmd-card-header"><span class="cmd-icon">⚡</span><span class="cmd-name">${escapeHtml(toolName.toUpperCase())}</span></div>
            <div class="cmd-syntax"><code>${escapeHtml(step.command)}</code></div>
            <p class="cmd-desc">${escapeHtml(step.description)}</p>
        </div>`;
    }
    const flagsHtml = Object.entries(tool.flags).map(([flag, desc]) =>
        `<div class="flag-item"><code>${escapeHtml(flag)}</code><span>${escapeHtml(desc)}</span></div>`
    ).join('');
    return `<div class="cmd-card">
        <div class="cmd-card-header">
            <span class="cmd-icon">${tool.icon}</span>
            <div class="cmd-title-group">
                <span class="cmd-name">${tool.name}</span>
                <span class="cmd-cat">${tool.cat}</span>
            </div>
            <span class="cmd-step-badge">STEP ${step.step_number}</span>
        </div>
        <p class="cmd-desc">${tool.desc}</p>
        <div class="cmd-syntax-block">
            <span class="syntax-label">SYNTAX</span>
            <code>${escapeHtml(tool.syntax)}</code>
        </div>
        <div class="cmd-used">
            <span class="used-label">USED AS</span>
            <code>${escapeHtml(step.command)}</code>
        </div>
        <div class="cmd-purpose"><strong>Purpose:</strong> ${escapeHtml(step.title)} — ${escapeHtml(step.description)}</div>
        <div class="cmd-flags">
            <span class="flags-label">FLAGS & OPTIONS</span>
            <div class="flags-grid">${flagsHtml}</div>
        </div>
    </div>`;
}

async function showCommandList() {
    showScreen('commands-screen');
    try {
        const res = await fetch('/api/scenarios');
        const scenarios = await res.json();
        const content = document.getElementById('commands-content');
        let html = '';
        for (const s of scenarios) {
            const detRes = await fetch(`/api/scenario/${s.id}`);
            const detail = await detRes.json();
            const cards = (detail.steps || []).map(step => {
                const toolName = step.command.split(' ')[0].toLowerCase();
                return getToolCard(toolName, step);
            }).join('');
            html += `<div class="command-scenario-group">
                <div class="command-scenario-header">
                    <h3>${s.name}</h3>
                    <span class="type-badge">${s.attack_type}</span>
                </div>
                <div class="cmd-cards-grid">${cards}</div>
            </div>`;
        }
        content.innerHTML = html;
    } catch (e) { console.error('Error loading commands:', e); }
}

// ===== Dashboard =====
async function showDashboard() {
    if (!currentUser) return;
    showScreen('dashboard-screen');
    try {
        const [dashRes, achRes] = await Promise.all([
            fetch(`/api/dashboard?username=${encodeURIComponent(currentUser.username)}`),
            fetch(`/api/achievements?username=${encodeURIComponent(currentUser.username)}`)
        ]);
        const dash = await dashRes.json();
        const achievements = await achRes.json();

        document.getElementById('dash-username').textContent = dash.username || currentUser.username;
        document.getElementById('dash-level-badge').textContent = `LVL ${dash.level || 1}`;
        document.getElementById('dash-level-name').textContent = dash.level_name || 'Recruit';
        document.getElementById('dash-xp-fill').style.width = (dash.xp_progress || 0) + '%';
        document.getElementById('dash-xp-label').textContent = `${dash.xp || 0} / ${(dash.level || 1) * 500} XP`;
        document.getElementById('dash-scenarios').textContent = `${dash.completed_scenarios || 0}/${dash.total_scenarios || 8}`;
        document.getElementById('dash-xp-total').textContent = dash.xp || 0;
        document.getElementById('dash-achievements').textContent = `${dash.achievements_unlocked || 0}/${dash.total_achievements || 12}`;
        document.getElementById('dash-level').textContent = dash.level || 1;

        const grid = document.getElementById('achievements-grid');
        grid.innerHTML = achievements.map(a => `
            <div class="ach-card ${a.unlocked ? 'unlocked' : 'locked'}">
                <span class="ach-icon-card">${a.icon}</span>
                <div class="ach-info">
                    <span class="ach-name">${a.name}</span>
                    <span class="ach-desc">${a.desc}</span>
                </div>
            </div>
        `).join('');
    } catch (e) { console.error('Error loading dashboard:', e); }
}

// ===== Luca Knowledge Base =====
let lucaActiveCategory = '';

async function showLuca() {
    showScreen('luca-screen');
    loadLuca();
}

async function loadLuca(search = '', category = '') {
    try {
        let url = '/api/luca';
        const params = [];
        if (search) params.push(`search=${encodeURIComponent(search)}`);
        if (category) params.push(`category=${encodeURIComponent(category)}`);
        if (params.length) url += '?' + params.join('&');

        const res = await fetch(url);
        const data = await res.json();

        // Render categories
        const catContainer = document.getElementById('luca-categories');
        catContainer.innerHTML = `<button class="luca-cat-btn ${!category ? 'active' : ''}" onclick="filterLucaCategory('')">All</button>` +
            (data.categories || []).map(c =>
                `<button class="luca-cat-btn ${category === c ? 'active' : ''}" onclick="filterLucaCategory('${c}')">${c}</button>`
            ).join('');

        // Render entries
        const entriesContainer = document.getElementById('luca-entries');
        entriesContainer.innerHTML = (data.entries || []).map(e => `
            <div class="luca-entry" onclick="trackLucaRead()">
                <h4>${escapeHtml(e.term)}</h4>
                <div class="luca-cat">${escapeHtml(e.category)}</div>
                <div class="luca-def">${escapeHtml(e.definition)}</div>
                <div class="luca-example">💡 ${escapeHtml(e.example)}</div>
            </div>
        `).join('');
    } catch (e) { console.error('Error loading Luca:', e); }
}

function searchLuca() {
    const search = document.getElementById('luca-search-input').value;
    loadLuca(search, lucaActiveCategory);
}

function filterLucaCategory(cat) {
    lucaActiveCategory = cat;
    const search = document.getElementById('luca-search-input')?.value || '';
    loadLuca(search, cat);
}

function trackLucaRead() {
    lucaReadCount++;
    if (lucaReadCount >= 10) unlockAchievement('knowledge_seeker');
}

// ===== Team Scoreboard =====
async function showTeamScoreboard() {
    showScreen('team-screen');
    loadTeams();
}

async function loadTeams() {
    try {
        const res = await fetch('/api/teams');
        const teams = await res.json();
        const container = document.getElementById('team-list');
        const maxScore = Math.max(...teams.map(t => t.total_score || 0), 1);
        container.innerHTML = teams.length === 0 ? '<p class="placeholder-text">No teams yet. Create one!</p>' :
            teams.map((t, i) => `
                <div class="team-card">
                    <span class="team-rank">#${i + 1}</span>
                    <div class="team-info">
                        <h3>${escapeHtml(t.team_name)}</h3>
                        <div class="team-members">${(t.members || []).join(', ')}</div>
                        <div class="team-score-bar"><div class="team-score-fill" style="width:${(t.total_score / maxScore * 100)}%"></div></div>
                    </div>
                    <span class="team-score">${t.total_score}</span>
                </div>
            `).join('');
    } catch (e) { console.error('Error loading teams:', e); }
}

async function createTeam() {
    const name = document.getElementById('team-name-input').value.trim();
    if (!name || !currentUser) return;
    try {
        const res = await fetch('/api/teams', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'create', team_name: name, username: currentUser.username })
        });
        const data = await res.json();
        if (data.error) { alert(data.error); return; }
        unlockAchievement('team_player');
        loadTeams();
        document.getElementById('team-name-input').value = '';
    } catch (e) { console.error('Error creating team:', e); }
}

async function joinTeam() {
    const name = document.getElementById('team-name-input').value.trim();
    if (!name || !currentUser) return;
    try {
        const res = await fetch('/api/teams', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'join', team_name: name, username: currentUser.username })
        });
        const data = await res.json();
        if (data.error) { alert(data.error); return; }
        unlockAchievement('team_player');
        loadTeams();
    } catch (e) { console.error('Error joining team:', e); }
}

// ===== Red vs Blue =====
function showRvB() { showScreen('rvb-screen'); }

function startRvBAttack() {
    currentMode = 'attack';
    showScreen('scenario-screen');
    document.getElementById('scenario-mode-title').textContent = '⚔️ Red vs Blue — Select Scenario (Attacker)';
    loadScenarios();
}

function startRvBDefend() {
    currentMode = 'detect';
    showScreen('scenario-screen');
    document.getElementById('scenario-mode-title').textContent = '⚔️ Red vs Blue — Select Scenario (Defender)';
    loadScenarios();
}

// ===== Tutorial =====
const tutorialSteps = [
    { title: 'Welcome to SPECTRA!', text: 'SPECTRA simulates real cyber attacks and forensic investigations. Choose Attack Mode (Red Team) or Detect Mode (Blue Team) to begin.' },
    { title: 'Attack Mode 🔴', text: 'Execute simulated attacks step-by-step using terminal commands. Each step generates forensic logs for later analysis.' },
    { title: 'Detect Mode 🔵', text: 'Analyze forensic logs, use grep and timeline commands, and submit your analysis to score points.' },
    { title: 'XP & Leveling ⭐', text: 'Earn XP by completing scenarios. Level up from Recruit to Elite. Track progress in the Dashboard.' },
    { title: 'Luca Knowledge Base 🧠', text: 'Explore cybersecurity concepts in Luca. Search terms, learn attack techniques, and earn the Knowledge Seeker badge.' },
    { title: 'Ready to Go! 🚀', text: 'Choose a mode from the home screen and start your cybersecurity journey. Good luck, agent!' }
];

function startTutorial() {
    tutorialStep = 0;
    document.getElementById('settings-panel').style.display = 'none';
    document.getElementById('tutorial-overlay').style.display = 'flex';
    renderTutorialStep();
}

function renderTutorialStep() {
    const step = tutorialSteps[tutorialStep];
    document.getElementById('tutorial-title').textContent = step.title;
    document.getElementById('tutorial-text').textContent = step.text;

    const indicator = document.getElementById('tutorial-step-indicator');
    indicator.innerHTML = tutorialSteps.map((_, i) =>
        `<div class="tutorial-dot ${i === tutorialStep ? 'active' : ''}"></div>`
    ).join('');

    const nextBtn = document.getElementById('btn-tutorial-next');
    nextBtn.textContent = tutorialStep === tutorialSteps.length - 1 ? 'Finish ✓' : 'Next →';
}

function tutorialNext() {
    if (tutorialStep < tutorialSteps.length - 1) {
        tutorialStep++;
        renderTutorialStep();
    } else {
        document.getElementById('tutorial-overlay').style.display = 'none';
    }
}

function tutorialPrev() {
    if (tutorialStep > 0) {
        tutorialStep--;
        renderTutorialStep();
    }
}

// ===== Utility =====
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
