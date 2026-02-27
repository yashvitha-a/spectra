# SPECTRA — Cyber Forensics Training Simulator

> A dual-mode cybersecurity training platform where students experience both sides of a cyber attack — learning how attacks leave forensic evidence and how defenders investigate incidents.

**Team Spectra** • Maharaja Institute of Technology Mysore

---

## ✨ Features

### Core Modes
| Mode | Description |
|------|-------------|
| 🔴 **Attack Mode** | Execute simulated cyber attacks step-by-step using terminal commands |
| 🔵 **Detect Mode** | Analyze forensic logs, reconstruct timelines, and identify evidence |
| ⚔️ **Red vs Blue** | Multiplayer — one player attacks while the other investigates |
| 📋 **Command List** | Full reference of all commands with flag explanations (hover for details) |

### 8 Attack Scenarios
| # | Scenario | Difficulty | Real-World Parallel |
|---|----------|-----------|---------------------|
| 1 | Phishing & Credential Theft | Beginner | 2020 Twitter breach |
| 2 | SQL Injection Attack | Intermediate | 2017 Equifax breach |
| 3 | Ransomware Deployment | Advanced | 2017 WannaCry |
| 4 | Insider Threat / Data Exfil | Advanced | 2020 SolarWinds |
| 5 | DDoS Attack | Intermediate | 2016 Mirai / Dyn |
| 6 | Man-in-the-Middle | Intermediate | 2015 Darkhotel APT |
| 7 | DNS Poisoning | Advanced | 2019 Sea Turtle |
| 8 | Supply Chain Attack | Advanced | 2021 ua-parser-js |

### Gamification & Progress
- **XP & Leveling** — Earn XP per scenario, level up from Recruit → Elite Hacker
- **12 Achievements** — First Blood, Speed Demon, Perfect Analyst, Red Master, and more
- **User Dashboard** — Track level, XP progress, completed scenarios, and badges
- **Team Scoreboard** — Create/join teams, compete on a ranked leaderboard

### Learning Tools
- **🧠 Luca (Knowledge Base)** — 20+ cybersecurity terms with definitions, examples, and category filters
- **❓ Interactive Tutorial** — Guided 6-step walkthrough for new users
- **📰 Real-World Case Studies** — After each scenario, see how the attack maps to a real-world incident
- **💡 Hint System** — Get tool hints without revealing the full command

### Terminal Features
- **Realistic CLI** — Simulated terminal with prompts, colored output, and step validation
- **Basic Linux Commands** — `ls`, `pwd`, `whoami`, `id`, `ifconfig`, `cat`, `cd`, `clear`, `history`, `uname`, `date`
- **Keyword-Only Help** — `help` shows tool names + hints, encouraging students to construct commands themselves
- **Command Logging** — All terminal activity is logged and viewable via `history`
- **Detect Mode Commands** — `grep`, `timeline`, `filter`, `analyze`, `count`, `noise`, `logs`

### Visualization
- **Attack Chain** — Step-by-step progress bar showing current position in the attack
- **Network Topology** — Animated SVG diagram with pulse rings, glow effects, directional edges, and emoji node icons per scenario
- **🌙/☀️ Theme Toggle** — Dark (cyber) and light mode with full UI adaptation

### Security
- **Randomized Log Noise** — Benign logs mixed into Detect Mode for realistic analysis
- **No Real Exploitation** — All attacks are simulated; no actual systems are compromised
- **Local Storage** — All data stays in a local SQLite database

---

## 🏗️ Architecture

```
hackothon_27/
├── app.py                    # Flask backend (API + DB init + 8 scenarios)
├── requirements.txt          # Python dependencies
├── forensics.db              # SQLite database (auto-created on first run)
├── templates/
│   └── index.html            # Single-page app (all screens)
└── static/
    ├── css/
    │   └── style.css         # Dark/light theme, animations, all components
    └── js/
        └── main.js           # Frontend logic, terminal, XP, achievements
```

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3, Flask, SQLite |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Fonts | Orbitron, Share Tech Mono (Google Fonts) |
| Database | SQLite3 (built into Python) |

---

## ⚡ Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run
```bash
python app.py
```

### 3. Open Browser
Navigate to **http://localhost:5000**

> The database is automatically created and populated on first launch. To reset all data, delete `forensics.db` and restart.

---

## 📖 How to Use

### Attack Mode (Red Team)
1. Enter your callsign at the welcome prompt
2. Click **Attack Mode** → Select a scenario
3. Use the terminal to execute each step (type `help` for tool hints)
4. Watch the **Attack Chain** progress and **Network Topology** update
5. View generated forensic logs in real-time
6. Complete all steps → Earn XP → Switch to Detect Mode

### Detect Mode (Blue Team)
1. Click **Detect Mode** → Select the same scenario
2. Analyze forensic logs (includes noise logs for realism)
3. Use commands: `grep <term>`, `timeline`, `filter <type>`, `analyze`, `noise`
4. Check findings in the checklist
5. Write your analysis and submit → Get scored + see the **Real-World Case Study**

### Additional Features
- **⚙️ Settings** → Access Dashboard, Luca, Teams, Red vs Blue, Tutorial
- **🧠 Luca** → Browse/search cybersecurity terms and concepts
- **🏆 Teams** → Create or join a team for competitive play
- **⚔️ Red vs Blue** → Choose attacker or defender role

---

## 🔧 API Endpoints

### Scenarios & Steps
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/scenarios` | List all scenarios |
| GET | `/api/scenario/<id>` | Scenario details with steps |
| GET | `/api/company-files/<id>` | Intel files for a scenario |
| GET | `/api/company-file/<id>` | Single file content |

### Sessions & Logs
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/execute-step` | Execute an attack step |
| GET | `/api/session-logs/<sid>` | Get session logs |
| GET | `/api/session-logs-with-noise/<sid>` | Logs + randomized noise |
| POST | `/api/analyze` | Submit analysis for scoring |

### User & Progress
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/user/profile` | Create/get user profile |
| POST | `/api/user/xp` | Award XP and check level-up |
| GET | `/api/dashboard?username=` | Dashboard stats |
| GET | `/api/achievements?username=` | All achievements with status |
| POST | `/api/achievements/unlock` | Unlock an achievement |

### Knowledge & Teams
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/luca` | Knowledge base (search/filter) |
| GET | `/api/teams` | Team leaderboard |
| POST | `/api/teams` | Create/join a team |
| GET | `/api/network-map/<id>` | Network topology data |

---

## 📝 Database Schema

| Table | Purpose |
|-------|---------|
| `scenarios` | Attack scenario definitions (8 scenarios) |
| `attack_steps` | Step-by-step commands and descriptions |
| `generated_logs` | Forensic evidence logs per session |
| `sessions` | User session tracking |
| `company_files` | Intel files for each scenario |
| `user_profiles` | Username, XP, level, completed scenarios |
| `achievements` | Unlocked achievements per user |
| `teams` | Team names, members, scores |
| `luca` | Knowledge base terms and definitions |

---

## 🎓 Learning Outcomes

- Understand how real cyber attacks are executed step-by-step
- Recognize forensic evidence left behind by attackers
- Practice log analysis, timeline reconstruction, and evidence correlation
- Learn cybersecurity terminology through the Luca knowledge base
- Connect simulated attacks to real-world incidents (case studies)
- Experience both offensive and defensive roles

---

## 👥 Team Spectra

- **Yashwitha A** — Lead Developer
- **Nidhi S** — Security Research
- **Syed Abdulla Nawaz** — UI/UX Design
- **Nitesh Raja Nagalu** — Backend Engineer
- **Monisha M S** — QA & Logic

---

## 📄 License

Educational project developed at Maharaja Institute of Technology Mysore.

---

**Built with ❤️ for cybersecurity education** • Version 2.0
