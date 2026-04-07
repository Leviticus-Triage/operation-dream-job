# MITRE ATT&CK Mapping — OrderBuddy Campaign

**Campaign ID:** `40abc1fa2901`  
**ATT&CK Version:** v14  
**Navigator Layer:** [`navigator-layer.json`](navigator-layer.json)

---

## Overview

The OrderBuddy campaign maps to **20 ATT&CK techniques** across **9 tactics**, demonstrating a sophisticated multi-phase operation consistent with Lazarus Group (DPRK) "Operation Dream Job" TTPs.

---

## Mapping

### Resource Development

| ID | Technique | Evidence |
|----|-----------|----------|
| **T1583.001** | Acquire Infrastructure: Domains | `orderbuddyapp.com` (Azure), `orderbuddyshop.com` (Hostinger BR) — two professionally built fake websites as campaign cover |
| **T1585.001** | Establish Accounts: Social Media | LinkedIn fake recruiter profile (`kendall-mareth-lopez-diaz-3a5437365`), LinkedIn company page (`/company/orderbuddyshop`) |

### Reconnaissance

| ID | Technique | Evidence |
|----|-----------|----------|
| **T1593.001** | Search Open Websites/Domains: Social Media | Target profiled via LinkedIn — outreach tailored to software developer role |

### Initial Access

| ID | Technique | Evidence |
|----|-----------|----------|
| **T1566.001** | Phishing: Spearphishing Attachment | `orderbuddy-main.zip` delivered as fake "coding assignment" |
| **T1566.002** | Phishing: Spearphishing Link | LinkedIn DM with download link, `gurucooldown.short.gy` redirector |

### Execution

| ID | Technique | Evidence |
|----|-----------|----------|
| **T1204.002** | User Execution: Malicious File | Victim opens folder (tasks.json auto-exec) or runs `npm run build` (webpack payload) |
| **T1059.007** | Command and Scripting Interpreter: JavaScript | webpack.config.js, test.js, p.js, njs_ryGnMe8.js — all JavaScript payloads |
| **T1059.006** | Command and Scripting Interpreter: Python | main_ryGnMe8.py — Python reverse shell with Base85+XOR+zlib encoding |

### Persistence

| ID | Technique | Evidence |
|----|-----------|----------|
| **T1053.005** | Scheduled Task/Job: Scheduled Task | `setInterval(callback, 615968)` — re-beacons every ~10.3 minutes, up to 3 cycles |

### Defense Evasion

| ID | Technique | Evidence |
|----|-----------|----------|
| **T1027** | Obfuscated Files or Information | 5-layer obfuscation: string-array rotation (60 shifts), XOR, Base64, Base85, zlib compression |
| **T1027.010** | Command Obfuscation | Shell commands hidden behind 208 whitespace characters in tasks.json |
| **T1036** | Masquerading | Malware disguised as legitimate VS Code/Webpack project structure. Fake config with "StakingGame" blockchain deployment |
| **T1497** | Virtualization/Sandbox Evasion | Anti-debug via recursive `toString()` console trap |

### Discovery

| ID | Technique | Evidence |
|----|-----------|----------|
| **T1082** | System Information Discovery | `os.hostname()`, `os.platform()`, `os.userInfo()`, `process.argv` collected and exfiltrated |
| **T1083** | File and Directory Discovery | `find`-based search for `.env`, `*.key`, `*.pem`, `*.sqlite`, `*.db` across home directory |

### Collection

| ID | Technique | Evidence |
|----|-----------|----------|
| **T1005** | Data from Local System | .env files, private keys (*.key, *.pem, id_rsa), SQLite databases, Python source |
| **T1552.001** | Unsecured Credentials: Credentials in Files | Chrome/Edge/Opera/Brave `Login Data`, `Cookies` SQLite databases (up to 200 profiles per browser) |
| **T1552.004** | Unsecured Credentials: Private Keys | `*.key`, `*.pem`, `id_rsa`, `*.p12`, `*.pfx`, `*.keystore` targeted by file exfiltrator (p.js) |

### Command and Control

| ID | Technique | Evidence |
|----|-----------|----------|
| **T1071.001** | Application Layer Protocol: Web Protocols | HTTP GET/POST to C2 on port 1244 (Express.js). Triple fallback: 147.124 → 38.92 → 66.235 |
| **T1105** | Ingress Tool Transfer | 4 payload modules downloaded: `/j/` (test.js), `/z/` (p.js), `/o/` (njs), `/cli/` (main.py) |

### Exfiltration

| ID | Technique | Evidence |
|----|-----------|----------|
| **T1041** | Exfiltration Over C2 Channel | `POST /keys` (system recon), `POST /uploads` (browser data, files) over HTTP port 1244 |
| **T1048** | Exfiltration Over Alternative Protocol | FTP (pyftpdlib on port 21), SSH (port 22) on active C2 server for large file transfers |

---

## Kill Chain Alignment

```
Phase                  Techniques
─────────────────────  ──────────────────────────────────────────
Resource Development   T1583.001, T1585.001
Reconnaissance         T1593.001
Initial Access         T1566.001, T1566.002
Execution              T1204.002, T1059.006, T1059.007
Persistence            T1053.005
Defense Evasion        T1027, T1027.010, T1036, T1497
Discovery              T1082, T1083
Collection             T1005, T1552.001, T1552.004
C2                     T1071.001, T1105
Exfiltration           T1041, T1048
```

---

## Detection Recommendations by Technique

| Technique | Detection Method |
|-----------|-----------------|
| T1566 | Email gateway scanning for ZIP attachments containing webpack.config.js, tasks.json |
| T1204.002 | Endpoint monitoring for VS Code spawning shell processes after folder open |
| T1059.007 | Monitor `node` execution in `~/.vscode/` directory |
| T1053.005 | Alert on periodic HTTP connections from `node` to external IPs |
| T1027 | YARA rules matching rotated Base64 fragments (`E3NS4xMTc=NjYuMjM1Lj`) |
| T1071.001 | Network IDS rules for HTTP on port 1244 |
| T1041 | Monitor POST requests with FormData fields (ts, type, hid, ss, cc) |
| T1048 | Alert on FTP connections to non-whitelisted external servers |
