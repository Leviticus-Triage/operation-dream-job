# Forensic Timeline

## Campaign Timeline

| Date | Event |
|------|-------|
| 2025-09-24 | `orderbuddyapp.com` last modified (React SPA deployed) |
| 2025-11-xx | DigiCert SSL issued for `orderbuddyapp.com` |
| 2026-01-xx | Let's Encrypt SSL issued for `orderbuddyshop.com` |
| 2026-02-19 | ZIP archive received via LinkedIn, SOA serial `2026021901` for `orderbuddyshop.com` |
| 2026-02-19 | Phase 1–2: Full static analysis and reverse engineering completed |
| 2026-02-19 | All 4 attack vectors identified, obfuscation fully broken |
| 2026-02-19 | Abuse reports drafted (Vercel, Tier.Net, Azure, short.gy, jsonkeeper, LinkedIn) |
| 2026-02-19 | BSI/CERT-Bund notified |
| 2026-02-22 | Polizei/LKA contacted via Internetwache |
| 2026-02-27 | Phase 3: Dynamic analysis started (Modus B — live C2) |
| 2026-02-27 23:10:49 UTC | `npm run build` executed in sandbox |
| 2026-02-27 23:10:49 | Primary C2 (147.124.202.225) returns RST |
| 2026-02-27 23:10:50 | Fallback C2 (38.92.47.157) delivers config |
| 2026-02-27 23:10:51 | Active C2 (66.235.175.117) receives first beacon |
| 2026-02-27 23:10:52–59 | 4 payloads downloaded, npm install, node test.js |
| 2026-02-27 23:11:04 | First exfiltration (POST /uploads) |
| 2026-02-27 23:21:38 | 2nd beacon cycle (setInterval fired) |
| 2026-02-27 23:31:59 | PCAP capture ended (21 min, 132 MB) |
| 2026-02-28 | YARA rules developed and verified against all samples |
| 2026-02-28 | BSI/CERT-Bund update with Phase 3 findings |
| 2026-02-28 | Tier.Net abuse report updated with 66.235.175.117 |
| 2026-02-28 | BSI, LKA, CSBW confirm Lazarus Group attribution |

---

## Dynamic Analysis Timeline (Minute by Minute)

```
23:10:49  [TRIGGER]  npm run build → webpack.config.js executes
23:10:49  [C2]       GET /s/40abc1fa2901 → 147.124.202.225:1244 → RST
23:10:50  [C2]       GET /s/40abc1fa2901 → 38.92.47.157:1244 → HTTP 200 (config)
23:10:50  [DECODE]   Base64: NjYuMjM1LjE3NS4xMTcscnlHbk1lOA== → 66.235.175.117,ryGnMe8
23:10:51  [EXFIL]    POST /keys → 66.235.175.117:1244 (system recon: hostname, platform, user)
23:10:52  [DOWNLOAD] GET /j/ryGnMe8 → test.js (20,971 bytes — credential stealer)
23:10:53  [DOWNLOAD] GET /p → package.json (327 bytes — malware dependencies)
23:10:54  [INSTALL]  cd ~/.vscode && npm install --silent
23:10:57  [EXECUTE]  node ~/.vscode/test.js (windowsHide: true)
23:10:59  [DOWNLOAD] GET /z/ryGnMe8 → p.js (10,560 bytes — file exfiltrator)
23:10:59  [DOWNLOAD] GET /o/ryGnMe8 → njs_ryGnMe8.js (27,415 bytes — SSH/FTP RAT)
23:10:59  [DOWNLOAD] GET /cli/ryGnMe8 → main_ryGnMe8.py (8,316 bytes — Python revshell)
23:11:04  [EXFIL]    POST /uploads → browser data (Login Data, Cookies)
23:11:xx  [PERSIST]  setInterval registered (615,968 ms ≈ 10.3 min)
    ...
23:21:38  [BEACON]   2nd cycle: GET /s/40abc1fa2901 → RST → config → beacon
23:21:39  [EXFIL]    POST /keys (2nd recon) + POST /uploads (2nd exfil)
    ...
23:31:59  [END]      PCAP capture terminated (21 min total)
```

---

## TCP Stream Map

| Stream | Source IP | Destination | Content |
|--------|----------|-------------|---------|
| 39 | sandbox | 147.124.202.225:1244 | GET /s/40abc1fa2901 → RST |
| 41 | sandbox | 38.92.47.157:1244 | GET /s/40abc1fa2901 → Config |
| 42 | sandbox | 66.235.175.117:1244 | POST /keys (1st beacon) |
| 43 | sandbox | 66.235.175.117:1244 | GET /j/ryGnMe8 → test.js |
| 44 | sandbox | 66.235.175.117:1244 | GET /p → package.json |
| 45–62 | sandbox | 66.235.175.117:1244 | npm registry + GET /z,o,cli |
| 63–64 | sandbox | 66.235.175.117:1244 | POST /uploads (1st exfil) |
| 68 | sandbox | 147.124.202.225:1244 | GET /s/ → RST (2nd cycle) |
| 69 | sandbox | 38.92.47.157:1244 | GET /s/ → Config (2nd cycle) |
| 76 | sandbox | 66.235.175.117:1244 | POST /keys (2nd beacon) |
| 77 | sandbox | 66.235.175.117:1244 | POST /uploads (2nd exfil) |
| 81 | sandbox | 147.124.202.225:1244 | GET /s/ → RST (3rd cycle) |
| 82 | sandbox | 38.92.47.157:1244 | GET /s/ → Config (3rd cycle) |
