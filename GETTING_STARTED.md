# 🚀 SPECTRA — Getting Started Guide

**Cyber Forensics Training Simulator**  
**Team Spectra | Maharaja Institute of Technology Mysore**

---

## ⚡ Quick Start (2 minutes)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run
```bash
python app.py
```

### 3. Open Browser
Go to **http://localhost:5000**

### 4. Enter Your Callsign
Type a username at the welcome prompt and click **Initialize**.

### 5. Start Playing!
- **Attack Mode** → Pick a scenario → Use the terminal to execute each step
- **Detect Mode** → Analyze forensic logs → Submit your investigation
- **⚙️ Settings** → Access Dashboard, Luca, Teams, Red vs Blue, Tutorial

---

## 🎮 Modes Overview

### 🔴 Attack Mode (Red Team)
1. Select a scenario (8 available — Phishing, SQLi, Ransomware, Insider Threat, DDoS, MITM, DNS Poisoning, Supply Chain)
2. Type `help` to see tool hints (only keywords shown — figure out the full command!)
3. Use basic Linux commands: `ls`, `pwd`, `whoami`, `cat <file>`, `history`, `clear`
4. Execute each step to generate forensic logs
5. Watch the **Attack Chain** progress and **Network Topology** update
6. Earn **XP** and unlock **achievements** when you finish

### 🔵 Detect Mode (Blue Team)
1. Select the same scenario to investigate
2. Logs include **noise** (benign entries) for realism
3. Use forensic commands:
   - `grep <keyword>` — Search logs
   - `timeline` — View evidence timeline
   - `filter <type>` — Filter by log type
   - `analyze` — Summary statistics
   - `noise` — Identify benign logs
   - `count` — Count logs by type
4. Check findings in the checklist, write your analysis, and submit
5. See your **score**, **XP earned**, and a **real-world case study**

### ⚔️ Red vs Blue (Multiplayer)
- One player attacks → Logs are generated
- Other player defends → Analyzes those logs
- Access via **⚙️ Settings → Red vs Blue**

---

## ⚙️ Settings Panel Features

Click the **⚙️ gear icon** (top-right) to access:

| Feature | What It Does |
|---------|-------------|
| 📊 **Dashboard** | View your level, XP bar, completed scenarios, achievements |
| 🧠 **Luca** | Knowledge base — 20+ cybersecurity terms, searchable by category |
| 🏆 **Team Scoreboard** | Create/join teams, compete on a leaderboard |
| ⚔️ **Red vs Blue** | Multiplayer attack vs defend mode |
| ❓ **Tutorial** | 6-step guided walkthrough for new users |

---

## 📋 Command List Page

Click **Command List** on the home screen to see all commands for all 8 scenarios. Each command word has a **dotted underline** — hover over it to see what each flag means.

---

## 🏅 Achievements

| Achievement | How to Unlock |
|------------|--------------|
| 🩸 First Blood | Complete your first scenario |
| ⚡ Speed Demon | Finish a scenario in under 5 minutes |
| 🎯 Perfect Analyst | Score 100% in Detect Mode |
| 🔴 Red Master | Complete all 8 attack scenarios |
| 📚 Knowledge Seeker | Read 10+ Luca entries |
| 🕵️ Shadow Analyst | Complete without using any hints |
| 💀 Malware Hunter | Complete the Ransomware scenario |
| 👥 Team Player | Join or create a team |

---

## 🔧 Troubleshooting

### Port 5000 in use
```bash
# Change port in app.py (last line):
app.run(debug=True, port=5001)
```

### Database issues / weird behavior
```bash
# Delete and restart:
del forensics.db    # Windows
rm forensics.db     # Mac/Linux
python app.py
```

### UI looks broken / stale
Press `Ctrl+Shift+R` to hard-refresh (clears browser cache).

### Nothing loads after login
Check the terminal running Flask for error messages. Press `F12` in browser → Console tab.

---

## 🎯 Presentation Demo (10 min)

1. **Intro (1 min)** — Explain dual-mode approach
2. **Attack Mode (3 min)** — Pick Phishing scenario, type `help`, execute steps, show attack chain & network topology
3. **Detect Mode (3 min)** — Analyze logs, use `grep`, check findings, submit → show score + case study
4. **Features (2 min)** — Show Dashboard, Luca, Theme toggle, Team Scoreboard
5. **Wrap-up (1 min)** — Discuss 8 scenarios, XP system, real-world case studies

---

## 📞 Quick Reference

| Task | Command |
|------|---------|
| Start app | `python app.py` |
| Stop app | `Ctrl+C` |
| Open browser | http://localhost:5000 |
| Reset database | Delete `forensics.db` and restart |
| Toggle theme | Click 🌙/☀️ (top-right) |

---

**Built with ❤️ by Team Spectra** • Version 2.0
