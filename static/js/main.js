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
        if (e.key === 'Enter') submitAuth();
    });
});

// ===== User System =====
async function apiFetch(url, options = {}) {
    const { data: { session } } = await supabaseClient.auth.getSession();
    const token = session ? session.access_token : null;
    if (token) {
        options.headers = { ...options.headers, 'Authorization': `Bearer ${token}` };
    }
    return fetch(url, options); // Still use native fetch internally
}

function initUser() {
    supabaseClient.auth.onAuthStateChange(async (event, session) => {
        if (session) {
            try {
                const res = await apiFetch('/api/user/profile', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: session.user.user_metadata?.username || session.user.email.split('@')[0] })
                });
                if (res.ok) {
                    currentUser = await res.json();
                    localStorage.setItem('spectra_user', JSON.stringify(currentUser));
                    document.getElementById('username-modal')?.classList.add('hidden');
                    updateHomeUserInfo();
                    
                    if (event === 'SIGNED_IN' && currentUser.xp === 0 && (!currentUser.completed_scenarios || currentUser.completed_scenarios === '[]')) {
                        startTutorial();
                    }
                }
            } catch (e) {
                console.error(e);
            }
        } else {
            currentUser = null;
            localStorage.removeItem('spectra_user');
            document.getElementById('username-modal')?.classList.remove('hidden');
        }
    });

    supabaseClient.auth.getSession().then(({ data: { session } }) => {
        if (!session) {
            document.getElementById('username-modal')?.classList.remove('hidden');
        } else {
            document.getElementById('username-modal')?.classList.add('hidden');
        }
    });
}

function switchAuthTab(tab) {
    document.getElementById('auth-error-msg').style.display = 'none';
    const isLogin = tab === 'login';
    document.getElementById('tab-login').style.borderColor = isLogin ? 'var(--cyan)' : 'transparent';
    document.getElementById('tab-login').style.color = isLogin ? 'var(--cyan)' : 'var(--text-dim)';
    document.getElementById('tab-register').style.borderColor = !isLogin ? 'var(--cyan)' : 'transparent';
    document.getElementById('tab-register').style.color = !isLogin ? 'var(--cyan)' : 'var(--text-dim)';
    document.getElementById('auth-username').style.display = isLogin ? 'none' : 'block';
    document.getElementById('btn-submit-auth').innerText = isLogin ? 'ACCESS SYSTEM' : 'REGISTER SYSTEM';
    document.getElementById('btn-submit-auth').dataset.tab = tab;
}

async function submitAuth() {
    const email = document.getElementById('auth-email').value.trim();
    const password = document.getElementById('auth-password').value;
    const err = document.getElementById('auth-error-msg');
    const tab = document.getElementById('btn-submit-auth').dataset.tab || 'login';

    if (!email || !password) {
        err.innerText = "Email and password required.";
        err.style.display = 'block';
        return;
    }

    err.style.display = 'none';
    const btn = document.getElementById('btn-submit-auth');
    btn.innerText = "PROCESSING...";
    btn.disabled = true;

    try {
        if (tab === 'register') {
            const username = document.getElementById('auth-username').value.trim();
            if (!username) throw new Error("Callsign missing.");
            
            const { data, error } = await supabaseClient.auth.signUp({ 
                email, password, options: { data: { username } }
            });
            if (error) throw error;
            if (data.user && data.user.identities && data.user.identities.length === 0) {
                throw new Error("User already exists");
            }
        } else {
            const { data, error } = await supabaseClient.auth.signInWithPassword({ email, password });
            if (error) throw error;
        }
    } catch (e) {
        err.innerText = e.message || "Authentication failed.";
        err.style.display = 'block';
        btn.innerText = tab === 'login' ? 'ACCESS SYSTEM' : 'REGISTER SYSTEM';
        btn.disabled = false;
    }
}

async function logout() {
    await supabaseClient.auth.signOut();
    document.getElementById('settings-panel').style.display = 'none';
}

function updateHomeUserInfo() {
    const bar = document.getElementById('user-info-bar');
    if (!currentUser) {
        if (bar) bar.style.display = 'none';
        return;
    }
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
        const res = await apiFetch('/api/scenarios');
        const scenarios = await res.json();
        const grid = document.getElementById('scenarios-list');
        
        // Group scenarios by difficulty
        const diffGroups = {
            'Beginner': [],
            'Intermediate': [],
            'Advanced': []
        };
        
        for (const s of scenarios) {
            if (!diffGroups[s.difficulty]) diffGroups[s.difficulty] = [];
            diffGroups[s.difficulty].push(s);
        }
        
        // Determine multiples needed based on screen size
        const isDesktop = window.innerWidth > 900; // typical breakpoint for 4 columns vs 2 columns depends on CSS. Assuming >900px is desktop.
        const multipleNeeded = isDesktop ? 4 : 2;
        
        let html = '';
        
        for (const [diff, group] of Object.entries(diffGroups)) {
            if (group.length === 0) continue;
            
            const levelClass = diff.toLowerCase();
            const levelIcon = diff === 'Beginner' ? 'I' : diff === 'Intermediate' ? 'II' : 'III';
            // Start a difficulty section
            html += `<div class="difficulty-header ${levelClass}" style="grid-column: 1 / -1;"><span class="diff-icon">Level ${levelIcon}</span> ${diff}</div>`;
            
            for (const s of group) {
                const rooms = currentMode === 'detect' && s.forensics_rooms ? s.forensics_rooms : (s.tryhackme_rooms || '');
                const roomLinks = rooms.split(';').filter(Boolean).map(r => {
                    const [name, url] = r.split('|');
                    return url ? `<a href="${url}" target="_blank" class="thm-link">${name}</a>` : '';
                }).join('');
                
                let isCompleted = false;
                try {
                    if (currentUser && currentUser.completed_scenarios) {
                        const comp = JSON.parse(currentUser.completed_scenarios);
                        if (comp.includes(s.id)) isCompleted = true;
                    }
                } catch(e) {}
                
                html += `<div class="scenario-card" onclick="selectScenario(${s.id})" style="position: relative;">
                    ${isCompleted ? '<div style="position: absolute; top: 10px; right: 10px; background: rgba(74, 222, 128, 0.1); color: var(--green); border: 1px solid var(--green); padding: 3px 8px; border-radius: 4px; font-size: 0.75rem;">✅ Completed</div>' : ''}
                    <h3>${s.name}</h3>
                    <p>${s.description}</p>
                    <div class="scenario-meta">
                        <span>${s.attack_type}</span>
                        <span class="diff-badge ${s.difficulty.toLowerCase()}">${s.difficulty}</span>
                    </div>
                    ${roomLinks ? `<div class="thm-rooms"><span class="thm-label">THM:</span>${roomLinks}</div>` : ''}
                </div>`;
            }
            
            // Add padding cards
            let remainder = group.length % multipleNeeded;
            if (remainder !== 0) {
                let paddingCards = multipleNeeded - remainder;
                for (let i = 0; i < paddingCards; i++) {
                    html += `<div class="scenario-card" style="opacity: 0.5; cursor: default; border-style: dashed;">
                        <h3>Coming Soon</h3>
                        <p>More scenarios are in active development. Stay tuned for new challenges!</p>
                        <div class="scenario-meta">
                            <span>In Development</span>
                            <span class="diff-badge" style="background: rgba(255,255,255,0.1); color: #aaa;">TBA</span>
                        </div>
                    </div>`;
                }
            }
        }
        
        grid.innerHTML = html;
        
    } catch (e) { console.error('Failed to load scenarios:', e); }
}

// Add a resize listener so it recalculates if the window geometry drastically changes
window.addEventListener('resize', () => {
    if (document.getElementById('scenario-screen')?.classList.contains('active')) {
        // Debounce slightly
        clearTimeout(window.resizeScenarioTimer);
        window.resizeScenarioTimer = setTimeout(loadScenarios, 300);
    }
});

async function selectScenario(id) {
    try {
        const [scenarioRes, filesRes] = await Promise.all([
            apiFetch(`/api/scenario/${id}`),
            apiFetch(`/api/company-files/${id}`)
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
        
        // Define the scenario title to display
        const displayTitle = scenarioGuides[id]?.title || currentScenario.name || 'Unknown Scenario';

        if (currentMode === 'attack') {
            const attackTitleEl = document.getElementById('attack-scenario-title');
            if (attackTitleEl) attackTitleEl.innerText = displayTitle;
            showScreen('attack-screen');
            renderAttackMode();
        } else {
            const detectTitleEl = document.getElementById('detect-scenario-title');
            if (detectTitleEl) detectTitleEl.innerText = displayTitle;
            showScreen('detect-screen');
            loadDetectLogs();
        }
    } catch (e) { console.error('Failed to load scenario:', e); }
}

// ===== Attack Mode =====

// Level Guides (like TryHackMe room descriptions)
const scenarioGuides = {
    1: { title: 'Phishing & Credential Theft', obj: 'Execute a full phishing attack chain from recon to lateral movement.', learn: ['Network scanning with <code>nmap</code>', 'Email crafting with <code>setoolkit</code>', 'Website cloning with <code>httrack</code>', 'Credential harvesting'], steps: ['Use <code>nmap</code> to scan the target domain', 'Use <code>setoolkit</code> to craft a phishing email', 'Clone the login page with <code>httrack</code>', 'Send spoofed email with <code>sendmail</code>', 'Listen for credentials with <code>harvest</code>', 'SSH into target with stolen creds'], context: 'The 2020 Twitter hack used social engineering. Phishing is the #1 attack vector in 91% of breaches. Attackers prey on human psychology rather than technical flaws, making it incredibly effective. Training employees to recognize these deceptive tactics is a critical first line of defense.' },
    2: { title: 'SQL Injection Attack', obj: 'Exploit a vulnerable web application to extract database contents.', learn: ['Directory enumeration with <code>dirb</code>', 'SQL injection with <code>sqlmap</code>', 'Database dumping', 'Data exfiltration'], steps: ['Discover hidden pages with <code>dirb</code>', 'Test for SQLi with <code>sqlmap</code> and URL params', 'List databases with <code>--dbs</code> flag', 'Dump data with <code>--dump</code>', 'Connect to DB with <code>psql</code>', 'Exfiltrate with <code>pg_dump</code>'], context: 'The 2017 Equifax breach exposed 147M records through an unpatched SQL injection vulnerability. SQLi occurs when user input is incorrectly handled by backend databases, allowing attackers to manipulate queries. Proper parameterization and input validation can entirely prevent this class of attack.' },
    3: { title: 'Malware & Ransomware', obj: 'Create and deploy ransomware to understand how file encryption attacks work.', learn: ['Payload generation with <code>msfvenom</code>', 'Reverse shells with <code>nc</code>', 'File encryption techniques', 'Anti-forensics with <code>shred</code>'], steps: ['Generate payload with <code>msfvenom</code>', 'Set up listener with <code>nc</code>', 'Deploy payload via <code>scp</code>', 'Encrypt files with ransomware tool', 'Shred evidence with <code>shred</code>', 'Anonymize with <code>tor-browser</code>'], context: 'WannaCry (2017) hit 200,000+ computers in 150 countries. Average ransom payment in 2023 was $1.5M. Modern ransomware operations often involve "double extortion," where data is both encrypted and stolen to force payment under threat of public release. Reliable offline backups are essential for recovery.' },
    4: { title: 'Insider Threat', obj: 'Simulate an insider abusing legitimate access to steal data.', learn: ['VPN tunneling and evasion', 'Database access patterns', 'Data exfiltration methods', 'Dark web operations'], steps: ['Connect via <code>vpn</code>', 'Run database queries with <code>psql</code>', 'Export data with <code>pg_dump</code>', 'Set up anonymous exfil server', 'Use credential spraying', 'Access dark web marketplace'], context: 'Edward Snowden leaked classified NSA documents in 2013. Insider threats account for 25% of data breaches. These attacks are particularly difficult to detect because the perpetrator already possesses valid credentials and network access. Organizations must rely on behavioral analytics and strict access controls.' },
    5: { title: 'DDoS Attack', obj: 'Orchestrate a distributed denial-of-service attack across multiple vectors.', learn: ['SYN flood attacks with <code>hping3</code>', 'Application-layer attacks with <code>slowloris</code>', 'Botnet coordination', 'DNS amplification'], steps: ['Launch SYN flood with <code>hping3</code>', 'Start slowloris attack', 'Activate botnet nodes', 'Execute DNS amplification', 'Layer application-level DDoS', 'Coordinate distributed attack'], context: 'GitHub survived a 1.3 Tbps DDoS attack in 2018. Mirai botnet took down major internet services in 2016. DDoS attacks aim to exhaust target resources, rendering services unavailable to legitimate users. Mitigation requires specialized edge-network defenses and traffic scrubbing capabilities.' },
    6: { title: 'Man-in-the-Middle', obj: 'Intercept network communications between two parties.', learn: ['ARP spoofing with <code>arpspoof</code>', 'Packet capture with <code>tcpdump</code>', 'SSL stripping', 'Session hijacking'], steps: ['Scan local network with <code>arp-scan</code>', 'ARP spoof the gateway with <code>arpspoof</code>', 'Start packet sniffing with <code>ettercap</code>', 'Strip HTTPS with <code>sslstrip</code>', 'Capture traffic with <code>tcpdump</code>', 'Extract tokens with <code>ferret</code>'], context: 'NSA PRISM program intercepted internet communications. MITM attacks are common on public WiFi. By inserting themselves between the victim and the gateway, attackers can silently read or modify traffic. The widespread adoption of strict HTTPS has mitigated many of these risks.' },
    7: { title: 'DNS Poisoning', obj: 'Manipulate DNS records to redirect victims to malicious sites.', learn: ['DNS zone transfers with <code>dig</code>', 'DNS spoofing with <code>dnschef</code>', 'Cache poisoning techniques', 'Website cloning'], steps: ['Perform zone transfer with <code>dig axfr</code>', 'Set up DNS proxy with <code>dnschef</code>', 'Poison DNS cache with <code>dnspoisoner</code>', 'Clone target site with <code>httrack</code>', 'Harvest credentials with <code>harvest</code>', 'Access bank portal with stolen cookies'], context: 'In 2019, Sea Turtle hackers hijacked DNS records of 40+ organizations across 13 countries. By corrupting DNS caches, attackers can redirect users to fraudulent websites without their knowledge, even if they type the correct URL. Implementing DNSSEC helps ensure the authenticity of DNS responses.' },
    8: { title: 'Supply Chain Attack', obj: 'Compromise a software supply chain to reach enterprise targets.', learn: ['Package registry manipulation', 'Backdoor creation with <code>msfvenom</code>', 'CI/CD pipeline attacks', 'Credential harvesting at scale'], steps: ['Publish trojanized npm package', 'Add backdoor with <code>msfvenom</code>', 'Deploy to CI/CD via <code>npm</code>', 'Set up listener with <code>nc</code>', 'Collect stolen data', 'Pivot to enterprise systems'], context: 'SolarWinds attack (2020) compromised 18,000+ organizations including US government agencies. Attackers infiltrate a trusted third-party vendor to distribute malware to their clients disguised as legitimate software updates. This vector is highly devastating and difficult to detect.' },
    9: { title: 'Cross-Site Scripting (XSS)', obj: 'Inject malicious scripts into a web app to steal user sessions.', learn: ['Input field discovery with <code>dirb</code>', 'XSS payload crafting', 'Cookie theft techniques', 'Session hijacking'], steps: ['Find input fields with <code>dirb</code>', 'Test reflected XSS with <code>curl</code>', 'Craft cookie stealer with <code>python3</code>', 'Deploy stored XSS via <code>curl POST</code>', 'Capture cookies with <code>nc</code>', 'Take over admin account with stolen session'], context: 'XSS is in the OWASP Top 10. British Airways was fined $230M after an XSS-based attack exposed 380K cards. By injecting JavaScript into web pages viewed by other users, attackers can steal session tokens or perform actions on behalf of the victim. Content Security Policies provide strong defense-in-depth against XSS.' },
    10: { title: 'Rogue Access Point', obj: 'Set up a fake WiFi hotspot to intercept wireless traffic.', learn: ['WiFi scanning with <code>airodump-ng</code>', 'Rogue AP setup with <code>hostapd-mana</code>', 'DHCP/DNS services with <code>dnsmasq</code>', 'Traffic interception'], steps: ['Scan networks with <code>airodump-ng</code>', 'Create rogue AP with <code>hostapd-mana</code>', 'Start DHCP with <code>dnsmasq</code>', 'Route traffic with <code>iptables</code>', 'Capture traffic with <code>tshark</code>', 'Steal credentials from captured packets'], context: 'Pineapple WiFi devices are used by pentesters and attackers alike on public networks. Attackers broadcast a familiar SSID (like "Starbucks WiFi") to trick devices into connecting automatically. Once connected, all unencrypted traffic flows directly through the attacker\'s hardware.' },
    11: { title: 'Rainbow Table Attack', obj: 'Crack password hashes using precomputed rainbow tables.', learn: ['Hash identification with <code>hashid</code>', 'Rainbow table attacks with <code>rcrack</code>', 'Dictionary attacks with <code>hashcat</code>', 'Password cracking strategies'], steps: ['Dump password hashes with <code>mysqldump</code>', 'Identify hash types with <code>hashid</code>', 'Run rainbow tables with <code>rcrack</code>', 'Use <code>hashcat</code> for remaining hashes', 'Crack admin passwords with <code>john</code>', 'Access systems with cracked credentials'], context: 'LinkedIn breach (2012) leaked 117M hashed passwords. 60% were cracked within weeks using rainbow tables. Rainbow tables trade storage space for computation speed by pre-computing hashes for millions of possible passwords. Using unique cryptographic "salts" for each password renders these tables useless.' },
    12: { title: 'Social Engineering', obj: 'Use psychological manipulation to gain unauthorized access.', learn: ['OSINT with <code>maltego</code>', 'Phishing campaigns with <code>gophish</code>', 'Vishing (phone-based SE)', 'Pretexting techniques'], steps: ['Gather intel with <code>maltego</code>', 'Build phishing campaign with <code>gophish</code>', 'Execute vishing call with <code>spoofcard</code>', 'Brute force with <code>hydra</code>', 'Access AD with <code>ldapsearch</code>', 'Exfiltrate via <code>smbclient</code>'], context: 'Kevin Mitnick was the world\'s most wanted hacker — he primarily used social engineering, not code. Attackers manipulate human emotions like fear, urgency, or helpfulness to bypass technical security controls entirely. Comprehensive security awareness training is the most effective countermeasure.' },
    13: { title: 'Cryptojacking', obj: 'Deploy cryptocurrency miners on compromised servers.', learn: ['Brute force SSH with <code>hydra</code>', 'Persistence with <code>crontab</code>', 'Crypto mining setup', 'Process hiding techniques'], steps: ['Scan for SSH services with <code>nmap</code>', 'Brute force login with <code>hydra</code>', 'Download miner with <code>curl</code>', 'Configure and start mining', 'Add to crontab for persistence', 'Monitor mining pool revenue'], context: 'Tesla\'s cloud servers were cryptojacked in 2018. Cryptojacking increased 400% in 2022. Instead of stealing data, attackers steal computing resources to mine cryptocurrency like Monero. This results in inflated cloud bills and degraded performance for legitimate services.' },
    14: { title: 'Backdoor Installation', obj: 'Install persistent backdoors on a compromised system.', learn: ['Vulnerability scanning', 'Exploit frameworks with <code>msfconsole</code>', 'Backdoor persistence', 'SSH key planting'], steps: ['Scan for vulnerabilities with <code>nmap</code>', 'Find exploits with <code>searchsploit</code>', 'Launch exploit with <code>msfconsole</code>', 'Install backdoor from meterpreter', 'Plant SSH keys for persistence', 'Check persistence and cleanup'], context: 'APT groups like Lazarus install backdoors that persist for years undetected. A backdoor allows an attacker to re-enter a compromised network at will, bypassing normal authentication mechanisms. Defending against backdoors requires continuous monitoring of system integrity and network egress traffic.' },
    15: { title: 'Privilege Escalation', obj: 'Escalate from low-privilege user to root/admin access.', learn: ['PrivEsc enumeration with <code>linpeas.sh</code>', 'SUID exploitation', 'Password cracking with <code>john</code>', 'Shadow file parsing'], steps: ['Run enum script with <code>linpeas.sh</code>', 'Find SUID binaries', 'Exploit SUID to get root', 'Dump shadow file with <code>unshadow</code>', 'Crack passwords with <code>john</code>', 'Add persistence as root'], context: 'Dirty COW (CVE-2016-5195) was a Linux kernel PrivEsc that affected servers for 9 years. Once attackers gain a foothold as a standard user, they hunt for misconfigurations or kernel vulnerabilities to elevate their permissions. Root access is required to install rootkits or access sensitive system credentials.' },
    16: { title: 'Session Hijacking', obj: 'Steal active web sessions via network sniffing.', learn: ['ARP spoofing with <code>arpspoof</code>', 'Packet capture with <code>wireshark</code>', 'Token extraction with <code>ferret</code>', 'Session replay with <code>hamster</code>'], steps: ['ARP spoof the network', 'Capture traffic with <code>wireshark</code>', 'Extract tokens with <code>ferret</code>', 'Sidejack sessions with <code>hamster</code>', 'Access admin panel with stolen session', 'Exfiltrate data via <code>curl</code>'], context: 'Firesheep (2010) demonstrated session hijacking on public WiFi, leading to HTTPS adoption. By capturing unencrypted session cookies, an attacker can impersonate a logged-in user without needing their password. Securely flagging cookies as HTTPOnly and Secure mitigates these attacks.' },
    17: { title: 'Spyware & Keyloggers', obj: 'Deploy spyware to monitor and exfiltrate user activity.', learn: ['Payload crafting with <code>msfvenom</code>', 'C2 frameworks', 'Keylogging techniques', 'Data exfiltration'], steps: ['Craft spyware payload with <code>msfvenom</code>', 'Set up C2 listener', 'Send spear-phishing email', 'Access victim via meterpreter', 'Deploy keylogger', 'Exfiltrate captured data'], context: 'Pegasus spyware by NSO Group was used to monitor journalists and activists in 45+ countries. Spyware silently records keystrokes, screen captures, and microphone audio, providing attackers with deep insight into a target\'s activities. Advanced variants can circumvent multi-factor authentication by stealing session tokens directly from memory.' },
    18: { title: 'Evil Twin Attack', obj: 'Create a cloned WiFi access point with captive portal.', learn: ['WiFi deauth with <code>aireplay-ng</code>', 'Evil twin with <code>fluxion</code>', 'Captive portal creation', 'Credential capture'], steps: ['Scan for targets with <code>airodump-ng</code>', 'Deauth clients with <code>aireplay-ng</code>', 'Launch evil twin with <code>fluxion</code>', 'Set up captive portal', 'Capture WPA passwords', 'Connect to real network with stolen credentials'], context: 'Evil twin attacks are extremely effective at airports, hotels, and coffee shops. Attackers forcefully disconnect users from a legitimate network and trick them into connecting to a malicious clone. They then deploy fake captive portals designed to steal login credentials or distribute malware.' },
    19: { title: 'WPA Handshake Capture', obj: 'Capture and crack a WPA 4-way handshake.', learn: ['Monitor mode with <code>airmon-ng</code>', 'Handshake capture with <code>airodump-ng</code>', 'Deauth attacks', 'WPA cracking with <code>aircrack-ng</code>'], steps: ['Enable monitor mode with <code>airmon-ng</code>', 'Capture traffic with <code>airodump-ng</code>', 'Send deauth with <code>aireplay-ng</code>', 'Verify handshake capture', 'Crack with <code>aircrack-ng</code>', 'Connect with cracked password'], context: 'KRACK attack (2017) showed fundamental weaknesses in WPA2 protocol affecting billions of devices. By capturing the cryptographic handshake established when a client connects to a router, attackers can crack the network password offline using powerful GPU rigs. Strong, complex passphrases remain the primary defense.' },
    20: { title: 'Pass the Hash', obj: 'Use stolen NTLM hashes for lateral movement without cracking them.', learn: ['Hash dumping with <code>mimikatz</code>', 'Pass-the-hash with <code>crackmapexec</code>', 'Impacket tools', 'Golden ticket creation'], steps: ['Dump hashes with <code>mimikatz</code>', 'Test hashes with <code>crackmapexec</code>', 'Get shell with <code>psexec.py</code>', 'Dump domain secrets with <code>secretsdump.py</code>', 'Create golden ticket with <code>ticketer.py</code>', 'Access domain controller'], context: 'NotPetya (2017) used pass-the-hash and EternalBlue to spread through corporate networks. In Windows environments, attackers don\'t always need to crack a password hash; they can simply present the raw hash to authenticate. Implementing Microsoft\'s LAPS and restricting administrative logon rights can slow this lateral movement.' },
    21: { title: 'Botnet C&C', obj: 'Build and manage a botnet command-and-control infrastructure.', learn: ['C2 frameworks with <code>covenant</code>', 'Bot management', 'DDoS orchestration', 'Distributed attacks'], steps: ['Set up C2 server', 'Generate implants with <code>covenant</code>', 'Deploy to compromised hosts', 'Enumerate bot network', 'Issue distributed commands', 'Launch coordinated attack'], context: 'Mirai botnet (2016) infected 600K+ IoT devices and took down DNS provider Dyn. Botnets are vast networks of compromised devices acting under the unified command of an attacker. They are frequently rented out as modular cybercrime services for spam distribution or DDoS attacks.' },
    22: { title: 'DLL Injection', obj: 'Inject malicious DLLs into running Windows processes.', learn: ['Process enumeration with <code>tasklist</code>', 'DLL payload creation', 'Injection via <code>rundll32.exe</code>', 'Process migration'], steps: ['List processes with <code>tasklist</code>', 'Create DLL payload with <code>msfvenom</code>', 'Inject DLL via <code>rundll32.exe</code>', 'Migrate to svchost.exe', 'Dump credentials', 'Clear event logs'], context: 'Stuxnet used DLL injection to manipulate SCADA systems and destroy Iranian nuclear centrifuges. By injecting code into legitimate, trusted processes like explorer.exe, attackers can hide their malware from rudimentary antivirus scans. Advanced EDR solutions are required to detect these memory-resident anomalies.' },
    23: { title: 'SSRF Attack', obj: 'Exploit server-side request forgery to access internal resources.', learn: ['SSRF testing with <code>burpsuite</code>', 'AWS metadata exploitation', 'Internal service discovery', 'Cloud credential theft'], steps: ['Scan with <code>nmap</code>', 'Test SSRF with <code>burpsuite</code>', 'Access AWS metadata endpoint', 'Extract IAM credentials', 'Access S3 buckets with <code>aws</code> CLI', 'Exfiltrate data with <code>rclone</code>'], context: 'Capital One breach (2019) used SSRF to access AWS metadata and steal 106M customer records. SSRF forces a vulnerable server to make HTTP requests on behalf of the attacker, allowing them to bypass firewalls and interact with internal network components. Strict URL validation and network segmentation limit SSRF impact.' },
    24: { title: 'Advanced Ransomware', obj: 'Execute a double-extortion ransomware attack.', learn: ['RDP exploitation', 'Data exfiltration before encryption', 'Volume shadow deletion', 'Ransom negotiation'], steps: ['Brute force RDP with <code>hydra</code>', 'Enumerate shares with <code>smbclient</code>', 'Exfiltrate data with <code>rclone</code>', 'Delete backups with <code>vssadmin</code>', 'Deploy ransomware binary', 'Cover tracks'], context: 'Colonial Pipeline (2021) paid $4.4M ransom. Double extortion is now used in 70% of ransomware attacks. Modern ransomware gangs operate like corporate entities with dedicated negotiators and customer support. They systematically destroy local backups before deploying the encryption payload to maximize damage.' },
    25: { title: 'Kerberoasting', obj: 'Extract and crack Kerberos service tickets for domain access.', learn: ['AD enumeration with <code>bloodhound</code>', 'SPN scanning with <code>GetUserSPNs.py</code>', 'Ticket cracking', 'Domain admin escalation'], steps: ['Enumerate AD with <code>bloodhound-python</code>', 'Find SPNs with <code>GetUserSPNs.py</code>', 'Crack tickets with <code>hashcat</code>', 'Access service as admin', 'Dump domain secrets', 'Create golden ticket'], context: 'Kerberoasting requires only a domain user account and can compromise entire AD forests. Attackers request service tickets for specific accounts and then take those tickets offline to crack the underlying password hash. Using long, complex passwords for service accounts significantly mitigates this vulnerability.' },
    26: { title: 'Physical Device Cloning', obj: 'Clone a physical device and extract credentials from the image.', learn: ['Disk imaging with <code>dd</code>', 'Loop mounting with <code>losetup</code>', 'File recovery with <code>photorec</code>', 'Credential extraction'], steps: ['Create disk image with <code>dd</code>', 'Mount image with <code>losetup</code>', 'Recover files with <code>photorec</code>', 'Extract passwords with <code>lazagne.py</code>', 'Crack found hashes', 'Access online accounts'], context: 'Physical access attacks are a major concern for government agencies and high-security facilities. If an attacker gains hands-on access to an unencrypted device, they can simply image the hard drive and extract sensitive data at their leisure. Full-disk encryption like BitLocker or FileVault is the standard defense.' },
    27: { title: 'Watering Hole Attack', obj: 'Compromise a trusted website to target specific organizations.', learn: ['Web vulnerability scanning', 'Exploit injection', 'C2 beacon deployment', 'Targeted attacks'], steps: ['Scan target website with <code>nmap</code>', 'Find vulnerabilities with <code>burpsuite</code>', 'Inject exploit code', 'Set up C2 with <code>covenant</code>', 'Wait for target employees to visit', 'Establish persistent access'], context: 'APT groups like Lazarus use watering hole attacks to target defense and finance sectors. Instead of attacking a heavily fortified target directly, adversaries compromise a niche website known to be frequented by the target\'s employees. This effectively bypasses perimeter defenses by turning trusted sites into malware vectors.' },
    28: { title: 'Advanced Insider Attack', obj: 'Use legitimate access to steal data with anti-forensics techniques.', learn: ['Database querying', 'Steganography with <code>steghide</code>', 'Encrypted volumes with <code>veracrypt</code>', 'Anti-forensics'], steps: ['Query customer database', 'Hide data with <code>steghide</code>', 'Create encrypted volume with <code>veracrypt</code>', 'Transfer via personal email', 'Shred evidence files', 'Clear audit logs'], context: 'A Tesla employee stole trade secrets by exfiltrating data through personal cloud storage in 2023. Advanced insiders utilize encryption and steganography to disguise stolen data as benign files during exfiltration. Detecting these sophisticated plots requires deep integration of Data Loss Prevention (DLP) across all endpoints.' },
    29: { title: 'Zero-Day Exploitation', obj: 'Discover and exploit an unknown vulnerability.', learn: ['Fuzzing with <code>afl-fuzz</code>', 'Crash analysis with <code>gdb</code>', 'ROP chain building with <code>ropper</code>', 'Exploit development'], steps: ['Fuzz application with <code>afl-fuzz</code>', 'Analyze crash with <code>gdb</code>', 'Find ROP gadgets with <code>ropper</code>', 'Build exploit payload', 'Deploy reverse shell', 'Patch and persist'], context: 'Log4Shell (2021) was a zero-day in Log4j that affected millions of servers worldwide. Zero-days are flaws unknown to the software vendor, making them impossible to patch ahead of time and highly coveted by intelligence agencies. Defense strategies rely heavily on robust web application firewalls and behavior-based heuristic detection.' },
    30: { title: 'Living Off the Land', obj: 'Use only built-in Windows tools (LOLBins) to avoid detection.', learn: ['File download with <code>certutil</code>', 'Remote execution with <code>wmic</code>', 'Persistence with <code>schtasks</code>', 'Lateral movement with <code>psexec</code>'], steps: ['Download payload with <code>certutil</code>', 'Execute via <code>wmic</code>', 'Add persistence with <code>schtasks</code>', 'Move laterally with <code>psexec</code>', 'Exfiltrate via <code>powershell</code> DNS', 'Clear logs with <code>wevtutil</code>'], context: 'APT29 (Cozy Bear) extensively uses LOLBins to blend in with normal Windows operations. By utilizing tools that are natively installed on the operating system—like PowerShell or WMI—attackers avoid deploying custom malware binaries that trigger antivirus alarms. This makes their activity incredibly difficult to distinguish from legitimate administrative tasks.' },
};

function renderLevelGuide() {
    const panel = document.getElementById('level-guide-panel');
    if (!panel || !currentScenario) { if (panel) panel.style.display = 'none'; return; }

    // Use DB guide or JS fallback
    const dbGuide = currentScenario.guide;
    const jsGuide = scenarioGuides[currentScenario.id];

    if (dbGuide) {
        // Strip the "How to Clear" section if it exists in the fetched HTML to handle existing DB entries
        const cleanDbGuide = dbGuide.replace(/<h4>How to Clear<\/h4>\s*<ul>.*?<\/ul>/is, '');
        
        panel.style.display = 'block';
        panel.innerHTML = `
            <div class="level-guide-header" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'block' : 'none'">
                <h3>Mission Briefing</h3>
                <span class="intel-toggle">▼</span>
            </div>
            <div class="level-guide-body">${cleanDbGuide}</div>`;
    } else if (jsGuide) {
        panel.style.display = 'block';
        panel.innerHTML = `
            <div class="level-guide-header" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'block' : 'none'">
                <h3>Mission Briefing</h3>
                <span class="intel-toggle">▼</span>
            </div>
            <div class="level-guide-body">
                <h4>Objective</h4><p>${jsGuide.obj}</p>
                <h4>What You'll Learn</h4><ul>${jsGuide.learn.map(l => '<li>' + l + '</li>').join('')}</ul>
                <h4>Real-World Context</h4><p>${jsGuide.context}</p>
            </div>`;
    } else {
        panel.style.display = 'none';
    }
}

function renderAttackMode() {
    renderAttackSteps();
    renderCompanyIntel();
    renderLevelGuide();
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
        const res = await apiFetch(`/api/network-map/${currentScenario.id}`);
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
        const res = await apiFetch(`/api/company-file/${fileId}`);
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

    // ===== Exploratory Command Matching =====
    // Users can explore commands freely — we guide them, not punish them
    const userCmd = cmd.trim().toLowerCase().replace(/\s+/g, ' ');
    const expectedCmd = currentAllowed.cmd.trim().toLowerCase().replace(/\s+/g, ' ');
    const userTokens = userCmd.split(/\s+/);
    const expectedTokens = expectedCmd.split(/\s+/);
    const userTool = userTokens[0];
    const expectedTool = expectedTokens[0];

    // Extract key parts from expected command
    const expectedFlags = expectedTokens.filter(t => t.startsWith('-') || t.startsWith('/'));
    const expectedArgs = expectedTokens.filter(t => !t.startsWith('-') && t !== expectedTool && t.length > 1);

    // Check what the user got right
    const toolCorrect = userTool === expectedTool;
    const userFlags = userTokens.filter(t => t.startsWith('-') || t.startsWith('/'));
    const matchedFlags = expectedFlags.filter(f => userCmd.includes(f));
    const matchedArgs = expectedArgs.filter(a => userCmd.includes(a));
    const flagRatio = expectedFlags.length > 0 ? matchedFlags.length / expectedFlags.length : 1;
    const argRatio = expectedArgs.length > 0 ? matchedArgs.length / expectedArgs.length : 1;

    // Accept if: right tool + enough flags/args (50%+ each), OR exact match
    const isCorrect = (userCmd === expectedCmd) ||
        (toolCorrect && flagRatio >= 0.5 && argRatio >= 0.4) ||
        (toolCorrect && stepFailCount >= 2); // Accept any attempt with right tool after 2 fails

    if (!isCorrect) {
        stepFailCount++;
        if (cmd.trim().toLowerCase() === 'reveal' || cmd.trim().toLowerCase() === 'giveup') {
            revealedSteps++;
            output.innerHTML += `<div class="error-reaction all-done">
                <span class="error-mascot">📖</span>
                <span class="mascot-text">The command for Step ${currentStep + 1} is:<br><code style="color:var(--green);font-size:1rem;font-weight:700;">${escapeHtml(currentAllowed.cmd)}</code><br><span style="font-size:0.7rem;color:var(--text-dim);">Type it in to continue.</span></span>
            </div>`;
            output.scrollTop = output.scrollHeight;
            return;
        }

        // === Educational Feedback ===
        let feedback = '';
        if (!toolCorrect) {
            // Wrong tool entirely — tell them which tool to use
            feedback = `<div class="cmd-feedback">
                <div class="feedback-wrong">Wrong tool: <code>${escapeHtml(userTool)}</code></div>
                <div class="feedback-hint">This step needs <code>${escapeHtml(expectedTool)}</code> — ${currentAllowed.hint || 'check the hint!'}</div>
                <div class="feedback-tip">Try: <code>${escapeHtml(expectedTool)} ...</code></div>
            </div>`;
        } else {
            // Right tool! Explain generally what is missing without giving the exact answer away
            const missingFlags = expectedFlags.filter(f => !userCmd.includes(f));
            const missingArgs = expectedArgs.filter(a => !userCmd.includes(a));

            feedback = `<div class="cmd-feedback">
                <div class="feedback-right">Correct tool: <code>${escapeHtml(expectedTool)}</code></div>
                ${missingFlags.length > 0 ? `<div class="feedback-hint">⚠️ Missing ${missingFlags.length} flag(s). Check the Command List!</div>` : ''}
                ${missingArgs.length > 0 ? `<div class="feedback-hint">⚠️ Missing required argument/target.</div>` : ''}
                ${stepFailCount >= 2 ? `<div class="feedback-tip">Almost! Try once more with the right tool — any reasonable attempt will be accepted.</div>` : ''}
            </div>`;
        }

        output.innerHTML += feedback;

        if (stepFailCount >= 3) {
            output.innerHTML += `<div class="error-reaction wrong-cmd">
                <span class="mascot-text">Struggling? Type <strong>reveal</strong> to see the answer (−50 XP), or just try <code>${escapeHtml(expectedTool)}</code> with any flags — we'll accept it!</span>
            </div>`;
        }
        output.scrollTop = output.scrollHeight;
        onCommandFailed();
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
        await apiFetch('/api/execute-step', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario_id: currentScenario.id, step_id: step.id, session_id: sessionId })
        });
        await loadAttackLogs();
    } catch (e) { console.error('Error executing step:', e); }

    currentStep++;
    renderAttackChain();
    onStepCompleted();

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

        // Award XP for completing attack mode (no banner here, banner shows on results screen)
        await awardXP(currentScenario.id, false);
        onScenarioCompleted();
    }
    output.scrollTop = output.scrollHeight;
}

async function loadAttackLogs() {
    try {
        const res = await apiFetch(`/api/session-logs/${sessionId}`);
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
async function awardXP(scenarioId, customXp = null, showBanner = false) {
    if (!currentUser) return;
    const difficulty = currentScenario?.difficulty || 'Beginner';
    const xpMap = { 'Beginner': 100, 'Intermediate': 200, 'Advanced': 300 };
    const xp = customXp !== null ? customXp : (xpMap[difficulty] || 100);

    try {
        const res = await apiFetch('/api/user/xp', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: currentUser.username, xp, scenario_id: scenarioId })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        currentUser.xp = data.xp;
        currentUser.level = data.level;
        currentUser.level_name = data.level_name;
        currentUser.completed_scenarios = JSON.stringify(data.completed_scenarios);
        localStorage.setItem('spectra_user', JSON.stringify(currentUser));
        updateHomeUserInfo();

        // Show XP award banner (only when on results screen)
        if (showBanner) {
            const xpDisplay = document.getElementById('xp-award-display');
            if (xpDisplay) {
                xpDisplay.style.display = 'block';
                document.getElementById('xp-award-text').textContent = `+${xp} XP earned! Level ${data.level} — ${data.level_name}`;
            }
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
        const res = await apiFetch('/api/achievements/unlock', {
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
const possibleFindings = {
    'phishing_email_detected': 'Phishing email with spoofed sender',
    'fake_domain_identified': 'Fake login domain identified',
    'credential_theft_found': 'Credential theft detected',
    'unauthorized_access_found': 'Unauthorized access / lateral movement',
    'sql_injection_detected': 'SQL Injection payload observed',
    'malware_activity_found': 'Malware activity / Meterpreter session',
    'insider_threat_detected': 'Suspicious insider behaviour',
    'data_exfiltration_found': 'Data exfiltration detected',
    'ddos_syn_flood': 'SYN flood attack detected',
    'ddos_amplification': 'DNS Amplification detected',
    'mitm_arp_spoof': 'ARP Spoofing detected',
    'mitm_session_hijack': 'Session hijacking observed',
    'dns_zone_transfer': 'Unauthorized Zone Transfer',
    'dns_cache_poison': 'DNS Cache poisoned',
    'supply_chain_compromise': 'Compromised npm package identified',
    'supply_chain_backdoor': 'Malicious backdoor in dependency',
    'xss_reflected': 'Reflected XSS payload observed',
    'xss_stored': 'Stored XSS payload in comments',
    'xss_cookie_theft': 'Session cookie exfiltration'
};

const scenarioFindingsMap = {
    1: ['phishing_email_detected', 'fake_domain_identified', 'credential_theft_found', 'unauthorized_access_found'],
    2: ['sql_injection_detected', 'credential_theft_found', 'unauthorized_access_found', 'data_exfiltration_found'],
    3: ['malware_activity_found', 'unauthorized_access_found'],
    4: ['insider_threat_detected', 'data_exfiltration_found'],
    5: ['ddos_syn_flood', 'ddos_amplification'],
    6: ['mitm_arp_spoof', 'mitm_session_hijack'],
    7: ['dns_zone_transfer', 'dns_cache_poison'],
    8: ['supply_chain_compromise', 'supply_chain_backdoor'],
    9: ['xss_reflected', 'xss_stored', 'xss_cookie_theft']
};

function switchToDetect() {
    currentMode = 'detect';
    showScreen('detect-screen');
    loadDetectLogs();
    
    // Only show findings relevant to this specific room/scenario
    const roomFindingsKeys = scenarioFindingsMap[currentScenario?.id] || Object.keys(possibleFindings);
    
    const container = document.getElementById('findings-checklist');
    if (container) {
        container.innerHTML = roomFindingsKeys.map(k => `
            <label class="check-item"><input type="checkbox" value="${k}"><span>${possibleFindings[k]}</span></label>
        `).join('');
    }
}

async function loadDetectLogs() {
    try {
        // Use noise endpoint for extra challenge
        const url = sessionId ? `/api/session-logs-with-noise/${sessionId}` : `/api/session-logs/${sessionId}`;
        const res = await apiFetch(url);
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

    if (!analysis.trim()) {
        alert('A written Analysis Report is required to complete the investigation.');
        return;
    }

    const btn = document.getElementById('btn-submit-analysis');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Analyzing...'; }

    try {
        const res = await apiFetch('/api/analyze-logs', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId, analysis, findings, scenario_id: currentScenario?.id })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const result = await res.json();
        
        // Update user's local progress by pulling fresh data from server
        if (currentUser) {
            const profileRes = await apiFetch('/api/user/profile');
            if (profileRes.ok) {
                currentUser = await profileRes.json();
                localStorage.setItem('spectra_user', JSON.stringify(currentUser));
                updateHomeUserInfo();
            }
        }
        
        showResults(result);
    } catch (e) {
        console.error('Error submitting analysis:', e);
        showResults({ score: 0, correct_findings: {}, message: 'Error submitting analysis. Please try again.' });
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = '📊 Submit Analysis'; }
    }
}

// Real-world case studies mapped to scenarios (multiple per scenario for variety)
const caseStudies = {
    1: [
        { title: '2020 Twitter Spear Phishing', desc: 'Attackers socially engineered Twitter employees via phone phishing to gain access to internal tools. They hijacked 130+ high-profile accounts (Obama, Musk, Apple) to promote a Bitcoin scam, stealing $120K.', steps: ['Step 1 (Recon): Attackers researched Twitter employees on LinkedIn', 'Step 2 (Phishing email): Sent via phone — vishing attack on IT support', 'Step 3 (Credential capture): Gained VPN credentials for internal tools', 'Step 4 (Lateral access): Used admin panel to take over verified accounts'] },
        { title: '2023 MGM Resorts Social Engineering', desc: 'Scattered Spider group called MGM IT helpdesk pretending to be an employee. They convinced the helpdesk to reset MFA, gaining access to Okta and Azure AD. The attack cost MGM over $100M and shut down casino operations for 10 days.', steps: ['Step 1 (Recon): Scraped employee info from LinkedIn and social media', 'Step 2 (Vishing): Called helpdesk impersonating a found employee', 'Step 3 (MFA bypass): Got helpdesk to reset multi-factor authentication', 'Step 4 (Lateral movement): Pivoted from Okta to Azure AD to deploy ransomware'] },
        { title: '2011 RSA SecurID Phishing', desc: 'Attackers sent a phishing email titled "2011 Recruitment Plan" with a malicious Excel attachment to RSA employees. The zero-day Flash exploit installed a backdoor, compromising 40 million SecurID tokens used by defense contractors worldwide.', steps: ['Step 1 (Recon): Identified low-level RSA employees as targets', 'Step 2 (Spear phish): Sent crafted Excel file exploiting CVE-2011-0609', 'Step 3 (Backdoor): Poison Ivy RAT installed via Flash zero-day', 'Step 4 (Exfiltration): SecurID seed data stolen, affecting Lockheed Martin and others'] }
    ],
    2: [
        { title: '2017 Equifax SQL Injection (CVE-2017-5638)', desc: 'Attackers exploited an Apache Struts vulnerability on Equifax servers. They accessed databases containing 147 million SSNs, birth dates, and credit data. Equifax paid $700M in settlements.', steps: ['Step 1-3 (Injection): Exploited input validation flaw in web framework', 'Step 4-5 (Data extraction): Queried credit history and PII tables', 'Step 6 (Exfiltration): Encrypted data exfiltrated over 76 days unnoticed'] },
        { title: '2023 MOVEit SQL Injection (CVE-2023-34362)', desc: 'Cl0p ransomware gang exploited a zero-day SQLi in MOVEit Transfer file sharing software. They stole data from 2,500+ organizations including Shell, BBC, British Airways, and US government agencies. Over 62 million individuals were affected.', steps: ['Step 1 (Reconnaissance): Cl0p identified MOVEit instances exposed to the internet', 'Step 2 (SQL injection): Exploited authentication bypass via crafted SQL payloads', 'Step 3 (Web shell): Deployed LEMURLOOT web shell for persistent access', 'Step 4 (Mass exfiltration): Automated data theft across thousands of victims simultaneously'] },
        { title: '2014 Sony Pictures SQL Injection & Breach', desc: 'Guardians of Peace (GOP) hackers breached Sony Pictures using SQL injection combined with social engineering. They leaked unreleased films, executive emails, salary data, and SSNs of 47,000 employees. Estimated damage exceeded $100M.', steps: ['Step 1 (Initial access): SQL injection on web-facing Sony infrastructure', 'Step 2 (Privilege escalation): Gained domain admin credentials from dumped tables', 'Step 3 (Lateral movement): Spread through internal network using stolen credentials', 'Step 4 (Data destruction): Deployed wiper malware after exfiltrating 100TB of data'] }
    ],
    3: [
        { title: '2017 WannaCry Ransomware', desc: 'WannaCry spread via EternalBlue (SMB exploit leaked from NSA). It encrypted files on 200,000+ machines across 150 countries. NHS hospitals, FedEx, and Telefonica were severely impacted.', steps: ['Step 1-2 (Payload + delivery): EternalBlue exploit auto-propagated via port 445', 'Step 3-4 (Execution + spread): Self-replicating worm encrypted files on each machine', 'Step 5-6 (Encrypt + ransom): AES-256 encryption with $300 BTC ransom per machine'] },
        { title: '2021 Kaseya REvil Ransomware', desc: 'REvil exploited a zero-day in Kaseya VSA (managed service provider software) to push ransomware to 1,500+ businesses simultaneously via trusted software updates. They demanded $70M in Bitcoin — the largest ransom ever at the time.', steps: ['Step 1 (Supply chain): Exploited Kaseya VSA authentication bypass (CVE-2021-30116)', 'Step 2 (Payload delivery): Disguised ransomware as legitimate Kaseya update', 'Step 3 (Mass deployment): Automated encryption across 1,500 downstream businesses', 'Step 4 (Ransom): $70M demand; FBI later recovered $6M through key recovery'] },
        { title: '2019 Norsk Hydro LockerGoga Ransomware', desc: 'LockerGoga ransomware hit aluminum manufacturer Norsk Hydro, forcing 35,000 employees across 40 countries to use pen and paper. The attack caused $71M in damages. The company refused to pay and rebuilt from backups.', steps: ['Step 1 (Initial access): Phishing email delivered trojan to employee workstation', 'Step 2 (Lateral movement): Attackers spent weeks mapping the network via Active Directory', 'Step 3 (Credential theft): Mimikatz harvested domain admin credentials', 'Step 4 (Encryption): LockerGoga deployed simultaneously across global infrastructure'] }
    ],
    4: [
        { title: '2020 SolarWinds Insider/Supply Chain', desc: 'Though primarily a supply chain attack, the SolarWinds breach involved insider-level access. Attackers inserted SUNBURST malware into Orion updates, affecting 18,000 organizations including US government agencies.', steps: ['Step 1-2 (Access + extraction): Attackers had code-level access for months', 'Step 3-4 (Exfiltration): Data sent to attacker-controlled cloud infrastructure', 'Step 5-6 (Cover tracks): Mimicked legitimate SolarWinds traffic patterns'] },
        { title: '2018 Tesla Insider Sabotage', desc: 'A disgruntled Tesla employee modified the Manufacturing Operating System source code and exported gigabytes of proprietary data to third parties. Elon Musk sent a company-wide email about the "extensive and damaging sabotage."', steps: ['Step 1 (Insider access): Employee had legitimate access to manufacturing systems', 'Step 2 (Code tampering): Modified production code causing manufacturing disruptions', 'Step 3 (Data exfiltration): Exported trade secrets to unknown external recipients', 'Step 4 (Cover-up): Created false usernames to disguise the changes'] },
        { title: '2020 Shopify Insider Data Theft', desc: 'Two rogue Shopify support team members abused their internal access to steal customer transaction data from nearly 200 merchants. They accessed names, emails, addresses, and order details before being identified and terminated.', steps: ['Step 1 (Abuse of access): Support staff exploited legitimate internal tools', 'Step 2 (Data harvesting): Systematically accessed merchant customer databases', 'Step 3 (Exfiltration): Exported PII and transaction records over several weeks', 'Step 4 (Detection): Internal anomaly detection flagged unusual data access patterns'] }
    ],
    5: [
        { title: '2016 Dyn DDoS (Mirai Botnet)', desc: 'The Mirai botnet harnessed 600,000 IoT devices (cameras, DVRs) to flood Dyn DNS with 1.2 Tbps. Twitter, Netflix, Reddit, and GitHub went down for hours across the US East Coast.', steps: ['Step 1-2 (Recon + botnet): Mirai scanned for IoT devices with default passwords', 'Step 3-4 (SYN + HTTP flood): Multi-vector attack saturated Dyn infrastructure', 'Step 5-6 (Amplification): DNS amplification multiplied attack traffic 50x'] },
        { title: '2018 GitHub 1.35 Tbps DDoS', desc: 'GitHub was hit with the then-largest DDoS attack ever recorded at 1.35 Tbps using Memcached amplification. Attackers spoofed UDP packets to open Memcached servers which amplified traffic 51,000x. GitHub was down for only 10 minutes thanks to Akamai Prolexic mitigation.', steps: ['Step 1 (Recon): Identified thousands of misconfigured Memcached servers on port 11211', 'Step 2 (Spoofing): Sent spoofed UDP requests with GitHub\'s IP as source', 'Step 3 (Amplification): Memcached servers amplified each packet by 51,000x', 'Step 4 (Mitigation): Akamai absorbed 1.35 Tbps and rerouted traffic within minutes'] },
        { title: '2020 AWS Shield DDoS (2.3 Tbps)', desc: 'An unnamed AWS customer was targeted with a 2.3 Tbps DDoS attack — the largest ever recorded. The attack used CLDAP reflection (Connection-less LDAP) to amplify traffic. AWS Shield Advanced mitigated it with zero customer impact.', steps: ['Step 1 (Target selection): Attacker identified high-value AWS-hosted service', 'Step 2 (CLDAP reflection): Exploited open LDAP servers for 56-70x amplification', 'Step 3 (Sustained attack): 2.3 Tbps sustained for several hours', 'Step 4 (Mitigation): AWS Shield scrubbed traffic at edge using anycast routing'] }
    ],
    6: [
        { title: '2015 Darkhotel APT (MITM)', desc: 'Darkhotel APT targeted executives at luxury hotels by compromising hotel WiFi. They used ARP spoofing and SSL stripping to intercept credentials and install keyloggers on business travelers laptops.', steps: ['Step 1-2 (Network + ARP): Compromised hotel WiFi routers for ARP spoofing', 'Step 3-5 (Capture + strip): Intercepted HTTPS traffic and harvested credentials', 'Step 6 (Session hijack): Used stolen sessions to access corporate email'] },
        { title: '2017 KRACK Attack (WPA2 MITM)', desc: 'Researchers discovered Key Reinstallation Attacks (KRACK) affecting ALL WPA2 WiFi implementations. Attackers within WiFi range could decrypt traffic, inject packets, and hijack TCP connections. Every WiFi device in the world was vulnerable.', steps: ['Step 1 (Proximity): Attacker positions within WiFi range of target network', 'Step 2 (Key reinstallation): Forces nonce reuse in WPA2 4-way handshake', 'Step 3 (Traffic decryption): Decrypts all WiFi traffic including HTTPS on Android/Linux', 'Step 4 (Injection): Injects malicious content into unencrypted HTTP connections'] },
        { title: '2019 Capital One SSRF + MITM', desc: 'A former AWS employee exploited a misconfigured WAF to perform SSRF attacks on Capital One\'s cloud infrastructure. She accessed 100 million credit applications, 140,000 SSNs, and 80,000 bank account numbers via AWS metadata service.', steps: ['Step 1 (Recon): Identified misconfigured WAF allowing SSRF via crafted HTTP requests', 'Step 2 (SSRF): Queried AWS EC2 metadata service (169.254.169.254) for IAM credentials', 'Step 3 (Credential theft): Obtained temporary AWS access keys with S3 permissions', 'Step 4 (Data exfiltration): Downloaded 700+ S3 buckets containing customer PII'] }
    ],
    7: [
        { title: '2019 Sea Turtle DNS Hijacking', desc: 'Sea Turtle (state-sponsored) targeted DNS registries and registrars across the Middle East. They modified DNS records to redirect traffic through attacker-controlled servers, intercepting credentials for government agencies.', steps: ['Step 1-3 (DNS compromise): Gained access to DNS registrars and poisoned records', 'Step 4-5 (Clone + harvest): Man-in-the-middle via cloned sites with valid SSL certs', 'Step 6 (Exploitation): Used stolen credentials for long-term espionage access'] },
        { title: '2018 MyEtherWallet BGP/DNS Hijack', desc: 'Attackers hijacked Amazon Route 53 DNS via BGP leak to redirect MyEtherWallet.com users to a phishing site in Russia. They stole $17M in Ethereum in just 2 hours using a valid SSL certificate from a compromised CA.', steps: ['Step 1 (BGP hijack): Announced false BGP routes for Amazon DNS server IPs', 'Step 2 (DNS redirect): Poisoned DNS responses for myetherwallet.com', 'Step 3 (Phishing site): Served cloned wallet interface with valid SSL certificate', 'Step 4 (Theft): Harvested private keys and drained $17M in ETH within 2 hours'] },
        { title: '2020 SolarWinds DNS Tunneling (SUNBURST)', desc: 'The SUNBURST backdoor used DNS queries to communicate with C2 servers, encoding stolen data into subdomain requests to avsvmcloud.com. The DNS-based C2 channel evaded nearly all security monitoring for 9 months.', steps: ['Step 1 (Beacon): Malware encoded victim identity into DNS CNAME queries', 'Step 2 (C2 channel): DNS responses directed malware to secondary C2 via HTTPS', 'Step 3 (Exfiltration): Sensitive data tunneled out via crafted DNS subdomain queries', 'Step 4 (Evasion): Traffic blended with legitimate Orion telemetry for 9+ months'] }
    ],
    8: [
        { title: '2021 ua-parser-js NPM Supply Chain Attack', desc: 'The ua-parser-js package (7M weekly downloads) was hijacked via a compromised maintainer account. Attackers published versions containing cryptominers and password stealers, affecting thousands of projects.', steps: ['Step 1-2 (Target + compromise): Maintainer account lacked MFA protection', 'Step 3-4 (Inject + publish): Malicious postinstall script added to the package', 'Step 5-6 (Collect + pivot): Cryptominer + credential stealer deployed on install'] },
        { title: '2021 Codecov Supply Chain Attack', desc: 'Attackers modified Codecov\'s Bash Uploader script to exfiltrate CI/CD environment variables (secrets, tokens, API keys) from 29,000 customers including Twitch, HashiCorp, and Confluent. The breach went undetected for 2 months.', steps: ['Step 1 (Initial compromise): Exploited a flaw in Codecov\'s Docker image build process', 'Step 2 (Script modification): Added a single line to exfiltrate env vars to attacker server', 'Step 3 (Silent collection): CI/CD secrets harvested from thousands of pipelines for 2 months', 'Step 4 (Downstream attacks): Stolen tokens used to access private repos and cloud infrastructure'] },
        { title: '2022 PyPI & NPM Typosquatting Wave', desc: 'Attackers uploaded 200+ malicious packages to PyPI and NPM with names similar to popular libraries (e.g., "colourama" instead of "colorama"). These packages contained info-stealers targeting Discord tokens, browser credentials, and crypto wallets.', steps: ['Step 1 (Typosquatting): Created packages with misspelled names of popular libraries', 'Step 2 (Payload hiding): Obfuscated malicious code in setup.py/postinstall scripts', 'Step 3 (Auto-execution): Malware ran automatically on pip install / npm install', 'Step 4 (Data theft): Exfiltrated Discord tokens, browser passwords, and crypto wallet keys via webhooks'] }
    ]
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

    // Display findings (only those relevant to the scenario)
    const roomFindingsKeys = scenarioFindingsMap[currentScenario?.id] || Object.keys(possibleFindings);
    const findingsContainer = document.getElementById('findings-results');
    const findings = result.correct_findings || {};
    findingsContainer.innerHTML = Object.entries(findings)
        .filter(([key, found]) => roomFindingsKeys.includes(key))
        .map(([key, found]) => `
            <div class="finding-result ${found ? 'found' : 'missed'}">
                <span class="icon">${found ? '✅' : '❌'}</span>
                <span class="label">${possibleFindings[key] || key.replace(/_/g, ' ')}</span>
            </div>
        `).join('');

    // Real-world case study — randomly pick one from the array
    const studies = caseStudies[currentScenario?.id];
    if (studies && studies.length > 0) {
        const caseStudy = studies[Math.floor(Math.random() * studies.length)];
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

    // XP for detect mode — show banner on results screen
    if (currentScenario) {
        awardXP(currentScenario.id, true);
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
    // New scenario tools (9-30)
    'python3': { icon: '🐍', name: 'PYTHON3', cat: 'Scripting', desc: 'Python interpreter. Used for exploit development, payload crafting, and automation of attack chains.', syntax: 'python3 -c "<code>"', flags: { '-c': 'Execute code string', '-m': 'Run module', '-u': 'Unbuffered output' } },
    'airodump-ng': { icon: '📡', name: 'AIRODUMP-NG', cat: 'WiFi Recon', desc: 'Wireless network scanner. Captures 802.11 frames and lists nearby access points with client info.', syntax: 'airodump-ng <interface>', flags: { '-c': 'Channel to monitor', '--bssid': 'Filter by AP MAC', '-w': 'Output file prefix', '--band': 'Frequency band (a/b/g)' } },
    'airmon-ng': { icon: '📻', name: 'AIRMON-NG', cat: 'WiFi Setup', desc: 'Wireless monitor mode manager. Puts WiFi adapters into monitor mode for packet capture.', syntax: 'airmon-ng start <iface>', flags: { 'start': 'Enable monitor mode', 'stop': 'Disable monitor mode', 'check': 'Check for interfering processes' } },
    'aireplay-ng': { icon: '💥', name: 'AIREPLAY-NG', cat: 'WiFi Attack', desc: 'Wireless packet injection tool. Sends deauth frames to disconnect clients and force handshake capture.', syntax: 'aireplay-ng --deauth <count> -a <bssid>', flags: { '--deauth': 'Deauth frame count', '-a': 'Target AP BSSID', '-c': 'Target client MAC', '--fakeauth': 'Fake authentication' } },
    'aircrack-ng': { icon: '🔓', name: 'AIRCRACK-NG', cat: 'WiFi Crack', desc: 'WPA/WPA2 key cracker. Performs dictionary attacks on captured 4-way handshakes to recover WiFi passwords.', syntax: 'aircrack-ng -w <wordlist> <capture>', flags: { '-w': 'Wordlist file', '-b': 'Target BSSID', '-l': 'Output key to file' } },
    'fluxion': { icon: '👻', name: 'FLUXION', cat: 'WiFi Attack', desc: 'Evil twin attack framework. Creates fake APs with captive portals to harvest WPA credentials.', syntax: 'fluxion --target <ssid> --attack captive_portal', flags: { '--target': 'Target SSID', '--attack': 'Attack type', '--channel': 'Channel number' } },
    'hostapd-mana': { icon: '📶', name: 'HOSTAPD-MANA', cat: 'Rogue AP', desc: 'Rogue access point tool. Creates fake WiFi hotspots with advanced credential interception capabilities.', syntax: 'hostapd-mana <config> --ssid <name>', flags: { '--ssid': 'Network name', '--channel': 'WiFi channel', '--wpa': 'Enable WPA' } },
    'dnsmasq': { icon: '🌐', name: 'DNSMASQ', cat: 'Network', desc: 'Lightweight DNS/DHCP server. Assigns IPs and resolves DNS for clients on rogue networks.', syntax: 'dnsmasq --dhcp-range=<start>,<end>', flags: { '--dhcp-range': 'IP range to assign', '--interface': 'Network interface', '--no-daemon': 'Run in foreground' } },
    'iptables': { icon: '🧱', name: 'IPTABLES', cat: 'Firewall', desc: 'Linux packet filter. Configures NAT rules to route victim traffic through attacker machine.', syntax: 'iptables -t nat -A PREROUTING ...', flags: { '-t': 'Table (nat/filter)', '-A': 'Append rule', '-j': 'Jump target', '--dport': 'Destination port' } },
    'tshark': { icon: '🦈', name: 'TSHARK', cat: 'Analysis', desc: 'Command-line Wireshark. Extracts specific fields from packet captures for automated analysis.', syntax: 'tshark -r <pcap> -Y <filter>', flags: { '-r': 'Read pcap file', '-Y': 'Display filter', '-T': 'Output format', '-e': 'Field to extract' } },
    'wireshark': { icon: '🦈', name: 'WIRESHARK', cat: 'Analysis', desc: 'Network protocol analyzer. Captures and inspects packets in real-time with deep protocol analysis.', syntax: 'wireshark -i <iface> -f <filter>', flags: { '-i': 'Capture interface', '-f': 'Capture filter', '-w': 'Write to file', '-k': 'Start capture immediately' } },
    'mysqldump': { icon: '🗄️', name: 'MYSQLDUMP', cat: 'Exfil', desc: 'MySQL database export tool. Dumps database tables including password hashes for offline cracking.', syntax: 'mysqldump -u <user> <database>', flags: { '-u': 'Username', '-p': 'Prompt for password', '--single-transaction': 'Consistent snapshot' } },
    'hashid': { icon: '🔎', name: 'HASHID', cat: 'Identify', desc: 'Hash type identifier. Detects the algorithm used to generate a hash (MD5, SHA, bcrypt, etc).', syntax: 'hashid -m <hash>', flags: { '-m': 'Show hashcat mode', '-j': 'Show John format', '-e': 'Extended analysis' } },
    'rcrack': { icon: '🌈', name: 'RCRACK', cat: 'Cracking', desc: 'Rainbow table cracker. Looks up precomputed hash-plaintext pairs for instant password recovery.', syntax: 'rcrack <table_dir> -h <hashes>', flags: { '-h': 'Hash file to crack', '-l': 'Hash list file', '-f': 'Specific hash value' } },
    'hydra': { icon: '🐉', name: 'HYDRA', cat: 'Brute Force', desc: 'Online password cracker. Tests credentials against live services (SSH, FTP, HTTP, RDP, etc).', syntax: 'hydra -L <users> -P <passwords> <target> <service>', flags: { '-L': 'Username list', '-P': 'Password list', '-t': 'Parallel tasks', '-vV': 'Verbose output' } },
    'maltego': { icon: '🕵️', name: 'MALTEGO', cat: 'OSINT', desc: 'OSINT and link analysis platform. Maps relationships between people, domains, IPs, and organizations.', syntax: 'maltego --target <org> --transform <type>', flags: { '--target': 'Investigation target', '--transform': 'Data transform type', '--depth': 'Recursion depth' } },
    'gophish': { icon: '🎣', name: 'GOPHISH', cat: 'Phishing', desc: 'Open-source phishing framework. Creates and manages phishing campaigns with tracking and reporting.', syntax: 'gophish --campaign <name>', flags: { '--campaign': 'Campaign name', '--template': 'Email template', '--targets': 'Target CSV file' } },
    'spoofcard': { icon: '📞', name: 'SPOOFCARD', cat: 'Social Eng', desc: 'Caller ID spoofing tool. Disguises phone number to impersonate trusted callers for vishing attacks.', syntax: 'spoofcard --caller-id <number>', flags: { '--caller-id': 'Number to display', '--target': 'Number to call', '--record': 'Record the call' } },
    'ldapsearch': { icon: '📒', name: 'LDAPSEARCH', cat: 'AD Recon', desc: 'LDAP query tool. Searches Active Directory for users, groups, and admin accounts.', syntax: 'ldapsearch -x -H <server> -b <base>', flags: { '-x': 'Simple auth', '-H': 'LDAP server URI', '-b': 'Search base DN', '-D': 'Bind DN' } },
    'smbclient': { icon: '📁', name: 'SMBCLIENT', cat: 'File Access', desc: 'SMB/CIFS client. Connects to Windows file shares to browse and download files remotely.', syntax: 'smbclient //<host>/<share> -U <user>', flags: { '-U': 'Username', '-L': 'List shares', '-c': 'Run command', '--no-pass': 'No password' } },
    'mimikatz': { icon: '🐱', name: 'MIMIKATZ', cat: 'Credential Dump', desc: 'Windows credential extraction tool. Dumps NTLM hashes, Kerberos tickets, and plaintext passwords from memory.', syntax: 'mimikatz "sekurlsa::logonpasswords"', flags: { 'privilege::debug': 'Enable debug privilege', 'sekurlsa::logonpasswords': 'Dump all passwords', 'lsadump::sam': 'Dump SAM database' } },
    'crackmapexec': { icon: '🗺️', name: 'CRACKMAPEXEC', cat: 'Lateral', desc: 'Network pentesting tool. Tests credentials across multiple hosts for pass-the-hash and lateral movement.', syntax: 'crackmapexec smb <target> -u <user> -H <hash>', flags: { '-u': 'Username', '-H': 'NTLM hash', '--shares': 'List shares', '-x': 'Execute command' } },
    'psexec.py': { icon: '🔧', name: 'PSEXEC.PY', cat: 'Remote Exec', desc: 'Impacket remote execution tool. Gets SYSTEM shell on remote Windows machines via SMB.', syntax: 'psexec.py <user>@<target>', flags: { '-hashes': 'NTLM hash (LM:NT)', '-k': 'Kerberos auth', '-dc-ip': 'Domain controller IP' } },
    'secretsdump.py': { icon: '🔐', name: 'SECRETSDUMP', cat: 'AD Dump', desc: 'Impacket AD secrets dumper. Extracts NTDS.dit, SAM hashes, and cached credentials remotely.', syntax: 'secretsdump.py <user>@<target>', flags: { '-hashes': 'NTLM hash', '-just-dc': 'Only NTDS.dit', '-system': 'SYSTEM hive' } },
    'ticketer.py': { icon: '🎟️', name: 'TICKETER', cat: 'Kerberos', desc: 'Kerberos ticket forger. Creates golden/silver tickets for persistent domain access.', syntax: 'ticketer.py -nthash <hash> -domain <dom>', flags: { '-nthash': 'krbtgt NTLM hash', '-domain-sid': 'Domain SID', '-domain': 'Domain name' } },
    'bloodhound-python': { icon: '🩸', name: 'BLOODHOUND', cat: 'AD Recon', desc: 'Active Directory enumeration tool. Maps attack paths from user to domain admin via graph analysis.', syntax: 'bloodhound-python -c all -d <domain>', flags: { '-c': 'Collection method', '-d': 'Target domain', '-u': 'Username', '-p': 'Password' } },
    'GetUserSPNs.py': { icon: '🎯', name: 'GETUSERSPNS', cat: 'Kerberoast', desc: 'Impacket SPN finder. Discovers service accounts and requests crackable Kerberos TGS tickets.', syntax: 'GetUserSPNs.py <domain>/<user>:<pass>', flags: { '-dc-ip': 'Domain controller IP', '-request': 'Request TGS tickets', '-outputfile': 'Save tickets to file' } },
    'linpeas.sh': { icon: '🐧', name: 'LINPEAS', cat: 'PrivEsc Enum', desc: 'Linux privilege escalation scanner. Finds SUID binaries, writable files, and kernel exploits automatically.', syntax: 'linpeas.sh | tee output.txt', flags: { '-a': 'All checks', '-s': 'Silent mode', '-P': 'Password to test' } },
    'john': { icon: '🔨', name: 'JOHN', cat: 'Cracking', desc: 'John the Ripper password cracker. Cracks password hashes using wordlists and brute force rules.', syntax: 'john --wordlist=<file> <hashes>', flags: { '--wordlist': 'Dictionary file', '--rules': 'Mangling rules', '--show': 'Show cracked', '--format': 'Hash format' } },
    'searchsploit': { icon: '🔍', name: 'SEARCHSPLOIT', cat: 'Exploit DB', desc: 'Exploit-DB search tool. Finds public exploits for specific software versions and CVEs.', syntax: 'searchsploit <keyword>', flags: { '-w': 'Show URL', '-m': 'Copy exploit to current dir', '--cve': 'Search by CVE' } },
    'unshadow': { icon: '👤', name: 'UNSHADOW', cat: 'Cracking', desc: 'Combines /etc/passwd and /etc/shadow into a single file for password cracking tools.', syntax: 'unshadow passwd shadow > hashes.txt', flags: {} },
    'tasklist': { icon: '📋', name: 'TASKLIST', cat: 'Windows Recon', desc: 'Windows process lister. Displays running processes with PID, memory usage, and service info.', syntax: 'tasklist /v /fi "<filter>"', flags: { '/v': 'Verbose output', '/fi': 'Filter criteria', '/svc': 'Show services per process' } },
    'rundll32.exe': { icon: '⚙️', name: 'RUNDLL32', cat: 'LOLBin', desc: 'Windows DLL loader. Legitimately loads DLLs — abused to execute malicious DLL payloads.', syntax: 'rundll32.exe <dll>,<entry>', flags: {} },
    'certutil': { icon: '📜', name: 'CERTUTIL', cat: 'LOLBin', desc: 'Windows certificate utility. Abused as a LOLBin to download files and encode/decode data.', syntax: 'certutil -urlcache -f <url> <output>', flags: { '-urlcache': 'URL cache mode', '-split': 'Split output', '-f': 'Force overwrite', '-encode': 'Base64 encode' } },
    'wevtutil': { icon: '📝', name: 'WEVTUTIL', cat: 'Anti-Forensics', desc: 'Windows event log utility. Used to clear security and system logs to cover attack tracks.', syntax: 'wevtutil cl <logname>', flags: { 'cl': 'Clear log', 'el': 'Enumerate logs', 'qe': 'Query events' } },
    'burpsuite': { icon: '🔎', name: 'BURPSUITE', cat: 'Web Proxy', desc: 'Web application security testing proxy. Intercepts and modifies HTTP requests for vulnerability scanning.', syntax: 'burpsuite --proxy --target <url>', flags: { '--proxy': 'Proxy mode', '--target': 'Target URL', '--scan': 'Active scan' } },
    'aws': { icon: '☁️', name: 'AWS CLI', cat: 'Cloud', desc: 'Amazon Web Services CLI. Manages AWS resources — used with stolen credentials for cloud exploitation.', syntax: 'aws s3 ls s3://<bucket>', flags: { 's3': 'S3 commands', '--profile': 'Named profile', 'ls': 'List contents', 'cp': 'Copy files' } },
    'rclone': { icon: '🔄', name: 'RCLONE', cat: 'Exfil', desc: 'Cloud storage sync tool. Transfers data to cloud remotes — abused for data exfiltration at scale.', syntax: 'rclone copy <src> <remote>:<path>', flags: { 'copy': 'Copy files', '--transfers': 'Parallel transfers', '--bwlimit': 'Bandwidth limit' } },
    'vssadmin': { icon: '💾', name: 'VSSADMIN', cat: 'Destruction', desc: 'Volume Shadow Copy admin. Ransomware uses it to delete backup snapshots before encryption.', syntax: 'vssadmin delete shadows /all /quiet', flags: { 'delete shadows': 'Delete snapshots', '/all': 'All shadow copies', '/quiet': 'No confirmation' } },
    'steghide': { icon: '🖼️', name: 'STEGHIDE', cat: 'Steganography', desc: 'Steganography tool. Hides data inside image and audio files to evade DLP detection.', syntax: 'steghide embed -cf <cover> -ef <data>', flags: { 'embed': 'Hide data in file', 'extract': 'Extract hidden data', '-cf': 'Cover file', '-ef': 'Embedded file', '-p': 'Passphrase' } },
    'veracrypt': { icon: '🔒', name: 'VERACRYPT', cat: 'Encryption', desc: 'Disk encryption with hidden volumes. Provides plausible deniability for stolen data storage.', syntax: 'veracrypt --create <volume>', flags: { '--create': 'Create volume', '--mount': 'Mount volume', '--encryption': 'Algorithm (AES, Twofish)' } },
    'photorec': { icon: '📸', name: 'PHOTOREC', cat: 'Recovery', desc: 'File recovery tool. Recovers deleted files from disk images — useful for both attackers and forensics.', syntax: 'photorec <disk_image>', flags: { '/d': 'Output directory', '/cmd': 'Command mode' } },
    'lazagne.py': { icon: '🔑', name: 'LAZAGNE', cat: 'Credential Dump', desc: 'Password recovery tool. Extracts saved passwords from browsers, email clients, and applications.', syntax: 'python3 lazagne.py all', flags: { 'all': 'All modules', 'browsers': 'Browser passwords only', '-oJ': 'JSON output' } },
    'dd': { icon: '💿', name: 'DD', cat: 'Disk Clone', desc: 'Disk duplicator. Creates bit-for-bit copies of storage devices for forensic analysis or cloning.', syntax: 'dd if=<src> of=<dest> bs=4M', flags: { 'if': 'Input file/device', 'of': 'Output file', 'bs': 'Block size', 'status': 'Show progress' } },
    'losetup': { icon: '🔗', name: 'LOSETUP', cat: 'Disk Mount', desc: 'Loop device manager. Associates disk image files with loop devices for mounting and analysis.', syntax: 'losetup -fP <image>', flags: { '-f': 'Find free device', '-P': 'Scan partitions', '-d': 'Detach device' } },
    'afl-fuzz': { icon: '🐛', name: 'AFL-FUZZ', cat: 'Fuzzing', desc: 'American Fuzzy Lop — coverage-guided fuzzer. Discovers crashes and vulnerabilities in binaries.', syntax: 'afl-fuzz -i <input> -o <output> -- <binary>', flags: { '-i': 'Input corpus dir', '-o': 'Output dir', '-m': 'Memory limit' } },
    'gdb': { icon: '🔬', name: 'GDB', cat: 'Debugging', desc: 'GNU debugger. Analyzes crashes, inspects memory, and develops exploits from vulnerability data.', syntax: 'gdb <binary> <core_dump>', flags: { '-ex': 'Execute command', 'bt': 'Backtrace', 'info registers': 'Show CPU registers' } },
    'ropper': { icon: '🧩', name: 'ROPPER', cat: 'Exploit Dev', desc: 'ROP gadget finder. Searches binaries for return-oriented programming gadgets to bypass DEP/NX.', syntax: 'ropper --file <binary> --search <gadget>', flags: { '--file': 'Target binary', '--search': 'Search for gadget', '--chain': 'Generate ROP chain' } },
    'wmic': { icon: '🖥️', name: 'WMIC', cat: 'LOLBin', desc: 'Windows Management Instrumentation CLI. Executes commands remotely using legitimate Windows infrastructure.', syntax: 'wmic process call create "<cmd>"', flags: { 'process': 'Process management', 'call create': 'Start new process', '/node': 'Remote computer' } },
    'schtasks': { icon: '⏰', name: 'SCHTASKS', cat: 'Persistence', desc: 'Windows task scheduler CLI. Creates scheduled tasks for persistent malware execution on boot/logon.', syntax: 'schtasks /create /tn <name> /tr <cmd>', flags: { '/create': 'Create task', '/tn': 'Task name', '/tr': 'Command to run', '/sc': 'Schedule type', '/ru': 'Run as user' } },
    'psexec': { icon: '🔧', name: 'PSEXEC', cat: 'Remote Exec', desc: 'Sysinternals remote execution tool. Runs commands on remote Windows systems via admin shares.', syntax: 'psexec \\\\<host> <command>', flags: { '-u': 'Username', '-p': 'Password', '-s': 'Run as SYSTEM', '-c': 'Copy program' } },
    'powershell': { icon: '⚡', name: 'POWERSHELL', cat: 'LOLBin', desc: 'Windows scripting shell. Powerful tool abused for fileless attacks, download cradles, and AD enumeration.', syntax: 'powershell -c "<command>"', flags: { '-c': 'Execute command', '-ep bypass': 'Skip execution policy', '-enc': 'Base64 encoded command', '-nop': 'No profile' } },
    'nmcli': { icon: '📡', name: 'NMCLI', cat: 'Network', desc: 'NetworkManager CLI. Manages WiFi connections — used to connect to networks with cracked credentials.', syntax: 'nmcli device wifi connect <ssid>', flags: { 'connect': 'Connect to network', 'password': 'WiFi password', 'list': 'List available networks' } },
    'netsh': { icon: '🌐', name: 'NETSH', cat: 'Windows Net', desc: 'Windows network configuration CLI. Extracts stored WiFi profiles and passwords from Windows systems.', syntax: 'netsh wlan show profiles', flags: { 'show profiles': 'List WiFi profiles', 'key=clear': 'Show password', 'export': 'Export profile XML' } },
    'covenant': { icon: '📡', name: 'COVENANT', cat: 'C2 Framework', desc: '.NET C2 framework. Manages implants with encrypted HTTPS communication for stealthy post-exploitation.', syntax: 'covenant --listeners add', flags: { '--listeners': 'Manage listeners', '--interact': 'Control beacon', '--command': 'Run command on target' } },
    'botnet-cli': { icon: '🤖', name: 'BOTNET-CLI', cat: 'C2', desc: 'Botnet management CLI. Enumerates bots, issues commands, and coordinates distributed attacks.', syntax: 'botnet-cli --command "<cmd>"', flags: { '--list-bots': 'Enumerate bots', '--command': 'Issue command', '--sort-by': 'Sort criteria' } },
    'c2_server.py': { icon: '📡', name: 'C2 SERVER', cat: 'C2', desc: 'Custom C2 server. Receives beacons from compromised machines and dispatches attack commands.', syntax: 'python3 c2_server.py --port <port>', flags: { '--port': 'Listen port', '--ssl': 'Enable encryption', '--beacon-interval': 'Check-in interval' } },
    'ransomware.exe': { icon: '🔒', name: 'RANSOMWARE', cat: 'Malware', desc: 'Advanced ransomware binary. Encrypts files with AES-256/RSA-2048 and drops ransom notes.', syntax: 'ransomware.exe --encrypt-all', flags: { '--encrypt-all': 'Encrypt everything', '--extension': 'Encrypted file ext', '--exclude': 'Skip directories' } },
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
        const res = await apiFetch('/api/scenarios');
        const scenarios = await res.json();
        const content = document.getElementById('commands-content');
        // Sort by difficulty
        const diffOrder = { 'Beginner': 1, 'Intermediate': 2, 'Advanced': 3 };
        scenarios.sort((a, b) => (diffOrder[a.difficulty] || 99) - (diffOrder[b.difficulty] || 99));
        // Search bar
        let html = `<div class="cmd-search-bar">
            <input type="text" id="cmd-search-input" placeholder="Search commands, tools, scenarios..." oninput="filterCommands(this.value)">
        </div>`;
        for (const s of scenarios) {
            const detRes = await apiFetch(`/api/scenario/${s.id}`);
            const detail = await detRes.json();

            // Deduplicate tools within the scenario
            const seenTools = new Set();
            const uniqueSteps = (detail.steps || []).filter(step => {
                const toolName = step.command.split(' ')[0].toLowerCase();
                if (seenTools.has(toolName)) return false;
                seenTools.add(toolName);
                return true;
            });

            const cards = uniqueSteps.map(step => {
                const toolName = step.command.split(' ')[0].toLowerCase();
                return getToolCard(toolName, step);
            }).join('');

            const cmdsStr = (detail.steps || []).map(st => st.command).join(' ').toLowerCase();
            html += `<div class="command-scenario-group" data-scenario="${escapeHtml(s.name.toLowerCase())}" data-commands="${escapeHtml(cmdsStr)}">
                <div class="command-scenario-header cmd-collapsible" onclick="toggleCommandGroup(this)">
                    <div class="cmd-header-left">
                        <span class="cmd-collapse-arrow">&#9654;</span>
                        <h3>${s.name}</h3>
                    </div>
                    <div class="cmd-header-right">
                        <span class="type-badge">${s.attack_type}</span>
                        <span class="diff-badge ${s.difficulty.toLowerCase()}">${s.difficulty}</span>
                    </div>
                </div>
                <div class="cmd-cards-grid cmd-collapsed">${cards}</div>
            </div>`;
        }
        content.innerHTML = html;
    } catch (e) { console.error('Error loading commands:', e); }
}

function toggleCommandGroup(header) {
    const grid = header.nextElementSibling;
    const arrow = header.querySelector('.cmd-collapse-arrow');
    grid.classList.toggle('cmd-collapsed');
    arrow.classList.toggle('cmd-expanded');
}

function filterCommands(query) {
    const q = query.toLowerCase().trim();
    document.querySelectorAll('.command-scenario-group').forEach(group => {
        const name = group.dataset.scenario || '';
        const cmds = group.dataset.commands || '';
        const match = !q || name.includes(q) || cmds.includes(q);
        group.style.display = match ? '' : 'none';
        // Auto-expand matching groups when searching
        if (match && q) {
            group.querySelector('.cmd-cards-grid').classList.remove('cmd-collapsed');
            const arrow = group.querySelector('.cmd-collapse-arrow');
            if (arrow) arrow.classList.add('cmd-expanded');
        }
    });
}

// ===== Dashboard =====
async function showDashboard() {
    if (!currentUser) return;
    showScreen('dashboard-screen');
    try {
        const [dashRes, achRes] = await Promise.all([
            apiFetch(`/api/dashboard?username=${encodeURIComponent(currentUser.username)}`),
            apiFetch(`/api/achievements?username=${encodeURIComponent(currentUser.username)}`)
        ]);
        const dash = await dashRes.json();
        const achievements = await achRes.json();

        document.getElementById('dash-username').textContent = dash.username || currentUser.username;
        document.getElementById('dash-level-badge').textContent = `LVL ${dash.level || 1}`;
        document.getElementById('dash-level-name').textContent = dash.level_name || 'Recruit';
        document.getElementById('dash-xp-fill').style.width = (dash.xp_progress || 0) + '%';
        document.getElementById('dash-xp-label').textContent = `${dash.xp || 0} / ${(dash.level || 1) * 500} XP`;
        document.getElementById('dash-scenarios').textContent = `${dash.completed_count || 0}/${dash.total_scenarios || 8}`;
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
        
        // Populate Completed Rooms
        try {
            const comp = JSON.parse(dash.completed_scenarios || '[]');
            const dashRoomsGrid = document.getElementById('dash-completed-rooms');
            if (comp.length === 0) {
                dashRoomsGrid.innerHTML = '<p style="color: var(--text-dim); text-align: center; width: 100%; grid-column: 1 / -1;">No rooms completed yet. Execute attacks to earn XP!</p>';
            } else {
                const scenRes = await apiFetch('/api/scenarios');
                const allScenarios = await scenRes.json();
                const completedScenarios = allScenarios.filter(s => comp.includes(s.id));
                dashRoomsGrid.innerHTML = completedScenarios.map(s => `
                    <div class="scenario-card" style="cursor: default; position: relative;">
                        <div style="position: absolute; top: 10px; right: 10px; color: var(--green); font-size: 0.8rem;">✅ Done</div>
                        <h3>${s.name}</h3>
                        <p>${s.description}</p>
                        <div class="scenario-meta">
                            <span>Analysis Logged</span>
                            <span class="diff-badge ${s.difficulty.toLowerCase()}">${s.difficulty}</span>
                        </div>
                    </div>
                `).join('');
            }
        } catch(e) { console.error('Error loading dash rooms:', e); }

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

        const res = await apiFetch(url);
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
        const res = await apiFetch('/api/teams');
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
        const res = await apiFetch('/api/teams', {
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
        const res = await apiFetch('/api/teams', {
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

// ===== Encouragement System (SPECTRA Buddy) =====
const encourageMessages = {
    stepComplete: [
        "Nice work, agent! One step closer to mastering this.",
        "You're building real skills here. Keep going!",
        "That was smooth! You've got a natural instinct for this.",
        "Step complete! Your toolkit is growing stronger.",
        "Well done! Every expert was once a beginner.",
        "Brilliant execution! The cyber world needs analysts like you.",
        "Another step conquered! You're on a roll.",
        "Clean work! That's how the pros do it."
    ],
    scenarioComplete: [
        "Mission accomplished! You should be proud of yourself.",
        "Incredible work, agent! Take a moment to appreciate what you just learned.",
        "Scenario complete! You're becoming a real cyber detective.",
        "You did it! Remember, real security teams use these exact techniques.",
        "Outstanding performance! Time to celebrate with a stretch break."
    ],
    keepTrying: [
        "Stuck? That's totally okay. The best analysts ask for help -- try 'hint'!",
        "Don't worry about getting it perfect. Learning is messy, and that's fine!",
        "Every wrong attempt teaches you something. You're still making progress!",
        "Take a breath. You've got this. Try checking the hint for guidance.",
        "Even expert hackers Google things all the time. No shame in learning!"
    ],
    breakReminder: [
        "You've been working hard! Take a 5-minute stretch break -- your brain will thank you.",
        "Hey agent, hydration check! Grab some water and rest your eyes for a moment.",
        "Time for a quick breather. Stand up, stretch, and come back refreshed!",
        "Your brain processes better after short breaks. Take a walk, then come back stronger.",
        "Pro tip: the best hackers take regular breaks. Step away for a few minutes!"
    ]
};

let encourageFailCount = 0;
let sessionStartTime = Date.now();
let lastBreakReminder = Date.now();

function showEncouragement(type) {
    const messages = encourageMessages[type];
    if (!messages) return;
    const msg = messages[Math.floor(Math.random() * messages.length)];

    // Create popup element
    const popup = document.createElement('div');
    popup.className = 'encourage-popup';
    popup.innerHTML = `
        <div class="encourage-content">
            <div class="encourage-glow"></div>
            <p>${msg}</p>
            <button class="encourage-close" onclick="this.parentElement.parentElement.remove()">Got it</button>
        </div>
    `;
    document.body.appendChild(popup);

    // Auto-remove after 6 seconds
    setTimeout(() => { if (popup.parentElement) popup.classList.add('encourage-fade-out'); }, 5000);
    setTimeout(() => { if (popup.parentElement) popup.remove(); }, 5800);
}

// Check for break reminders (every 30 minutes)
setInterval(() => {
    const elapsed = Date.now() - lastBreakReminder;
    if (elapsed > 30 * 60 * 1000) {
        showEncouragement('breakReminder');
        lastBreakReminder = Date.now();
    }
}, 60000);

// Hook into step completion
const _origHandleAttack = typeof handleAttackCommand === 'function' ? null : null;
function onStepCompleted() {
    encourageFailCount = 0;
    // Show encouragement every 2-3 steps (not every single one)
    if (Math.random() < 0.4) {
        setTimeout(() => showEncouragement('stepComplete'), 800);
    }
}

function onCommandFailed() {
    encourageFailCount++;
    if (encourageFailCount >= 3) {
        showEncouragement('keepTrying');
        encourageFailCount = 0;
    }
}

function onScenarioCompleted() {
    setTimeout(() => showEncouragement('scenarioComplete'), 1500);
}

async function promptRenameUser() {
    const newName = prompt("Enter your new agent name:");
    if (!newName || !newName.trim()) return;
    
    try {
        const res = await apiFetch('/api/user/rename', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: newName.trim() })
        });
        if (res.ok) {
            const result = await res.json();
            if (currentUser) {
                currentUser.username = result.username;
                localStorage.setItem('spectra_user', JSON.stringify(currentUser));
                updateHomeUserInfo();
            }
        } else {
            alert("Failed to rename user.");
        }
    } catch(e) {
        console.error("Error renaming:", e);
        alert("Failed to rename user.");
    }
}
