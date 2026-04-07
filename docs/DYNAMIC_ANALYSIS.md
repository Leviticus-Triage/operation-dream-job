# Phase 3 — Dynamic Analysis: Live C2 Contact

**Date:** February 27–28, 2026  
**Mode:** B (live malware, real C2 communication)  
**Trigger:** `npm run build` in sandboxed container  
**Duration:** 21 minutes | 64,139 frames | 132 MB PCAP

---

## Key Discovery

Dynamic analysis revealed a **previously unknown, active C2 server** (`66.235.175.117`) not discoverable through static analysis alone. The fallback C2 delivers its address via Base64-encoded config at runtime.

```
Malware → 147.124.202.225:1244 (RST — offline)
       → 38.92.47.157:1244    (Config: Base64 → 66.235.175.117,ryGnMe8)
       → 66.235.175.117:1244  (Active — payloads delivered, exfil accepted)
```

---

## Environment

| Component | Configuration |
|-----------|---------------|
| Container | Docker `phase3-analysis-live` |
| Network | Live internet (not isolated — real C2 contact) |
| Monitoring | tshark (PCAP), asciinema (shell), inotifywait (filesystem) |
| Trigger | `npm run build` → webpack → malware activation |
| Host verification | 10-point check post-analysis — host confirmed clean |

---

## Communication Sequence

| Rel. Time | Event | Direction | Bytes |
|-----------|-------|-----------|-------|
| T+0s | GET `/s/40abc1fa2901` → 147.124.202.225 | OUT | 322 |
| T+0s | RST from primary C2 | IN | 322 |
| T+1s | GET `/s/40abc1fa2901` → 38.92.47.157 | OUT | 585 |
| T+1s | HTTP 200 — Base64 config received | IN | 585 |
| T+2s | POST `/keys` → 66.235.175.117 | OUT | 907 |
| T+2s | HTTP 200 — Timestamp echo | IN | — |
| T+3s | GET `/j/ryGnMe8` — test.js | IN | 20,971 |
| T+4s | GET `/p` — package.json | IN | 327 |
| T+5s | `npm install --silent` in ~/.vscode | LOCAL | — |
| T+8s | `node test.js` launched | LOCAL | — |
| T+10s | GET `/o/ryGnMe8`, `/z/ryGnMe8`, `/cli/ryGnMe8` | IN | ~46 KB |
| T+15s | POST `/uploads` — browser data exfil | OUT | multi |
| T+649s | 2nd beacon cycle (setInterval) | OUT | — |
| T+650s | POST `/keys` + POST `/uploads` (2nd) | BOTH | — |

---

## Downloaded Payloads

| File | Size | Endpoint | Function |
|------|------|----------|----------|
| test.js | 20.9 KB | GET /j/ryGnMe8 | Browser credential stealer (Chrome, Edge, Opera, Brave) |
| p.js | 10.5 KB | GET /z/ryGnMe8 | File exfiltrator (.env, keys, certs, databases) |
| njs_ryGnMe8.js | 27.4 KB | GET /o/ryGnMe8 | SSH/FTP RAT (remote shell, file transfer) |
| main_ryGnMe8.py | 8.3 KB | GET /cli/ryGnMe8 | Python reverse shell (Base85+XOR+zlib) |
| package.json | 327 B | GET /p | Malware npm dependencies |

---

## C2 Server Fingerprint (66.235.175.117)

Nmap results:

| Port | Service | Version | Purpose |
|------|---------|---------|---------|
| 21 | FTP | pyftpdlib 1.0.0+ | Data exfiltration |
| 22 | SSH | tcpwrapped | Remote access |
| 80 | HTTP | tcpwrapped | — |
| 443 | HTTPS | tcpwrapped | — |
| 1244 | HTTP | Node.js Express | C2 API |

All endpoints were confirmed live and serving payloads at time of analysis.

---

## Exfiltration Detail

### POST /keys Fields

```
ts=1772233979269
type=ryGnMe8
hid=0293d7d55ada
ss=oqr
cc=5A1/sandbox/.../webpack
```

### POST /uploads

Multipart form-data with timestamps, victim ID, and file attachments (browser SQLite databases, credential files).

---

## Host Verification (Post-Analysis)

| Check | Result |
|-------|--------|
| Suspicious processes (C2 IPs, ryGnMe8) | Clean |
| Network connections to C2 | None active |
| `~/.vscode/` malware artifacts | Not present |
| Crontab / systemd timers | Clean |
| `/etc/hosts` manipulation | Clean |
| `/tmp` suspicious files | Clean |
| `.bashrc` / `.profile` changes | Clean |
| Docker container state | Stopped (exit 137) |
| Listening ports (1244, 21, 4444) | None |
| Shell history (C2 IPs) | Clean |

**Assessment:** Host was not compromised. All malware activity was confined to the Docker container.
