#!/bin/bash
# ================================================================
#  ORDERBUDDY MALWARE - INFECTION CHECK SCRIPT
#  
#  Dieses Script prüft NUR (read-only). Es löscht oder
#  verändert NICHTS auf dem System.
#
#  Ausführen:
#    chmod +x CHECK_INFECTION.sh
#    ./CHECK_INFECTION.sh 2>&1 | tee ~/infection_check_$(date +%Y%m%d_%H%M%S).log
#
#  Getestet auf: macOS, Linux
# ================================================================

set -uo pipefail

# macOS hat kein GNU timeout — portable Alternative
if ! command -v timeout &>/dev/null; then
    timeout() {
        local duration="$1"; shift
        perl -e 'alarm shift; exec @ARGV' "$duration" "$@" 2>/dev/null
        return $?
    }
    # Fallback falls auch kein perl (unwahrscheinlich auf macOS)
    if ! perl -e 'exit 0' 2>/dev/null; then
        timeout() {
            local duration="$1"; shift
            ( "$@" ) &
            local pid=$!
            ( sleep "$duration" && kill "$pid" 2>/dev/null ) &
            local killer=$!
            wait "$pid" 2>/dev/null
            local rc=$?
            kill "$killer" 2>/dev/null
            wait "$killer" 2>/dev/null
            return $rc
        }
    fi
fi

# Portable sha256 hash
sha256_hash() {
    if command -v shasum &>/dev/null; then
        shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1
    elif command -v sha256sum &>/dev/null; then
        sha256sum "$1" 2>/dev/null | cut -d' ' -f1
    else
        echo "(sha256 nicht verfügbar)"
    fi
}

# Portable file modification time
file_mtime() {
    if [ "$(uname)" = "Darwin" ]; then
        stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$1" 2>/dev/null
    else
        date -r "$1" "+%Y-%m-%d %H:%M:%S" 2>/dev/null
    fi
}

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
BLU='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

INFECTED=0
SUSPICIOUS=0
CLEAN_CHECKS=0

REPORT_FILE="$HOME/infection_report_$(date +%Y%m%d_%H%M%S).md"

log_header() {
    echo ""
    echo -e "${BLU}════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BLU}════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "" >> "$REPORT_FILE"
    echo "## $1" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

log_critical() {
    echo -e "  ${RED}[KRITISCH]${NC} $1"
    echo "- **KRITISCH:** $1" >> "$REPORT_FILE"
    INFECTED=$((INFECTED + 1))
}

log_warning() {
    echo -e "  ${YEL}[WARNUNG]${NC}  $1"
    echo "- **WARNUNG:** $1" >> "$REPORT_FILE"
    SUSPICIOUS=$((SUSPICIOUS + 1))
}

log_ok() {
    echo -e "  ${GRN}[OK]${NC}       $1"
    echo "- OK: $1" >> "$REPORT_FILE"
    CLEAN_CHECKS=$((CLEAN_CHECKS + 1))
}

log_info() {
    echo -e "  ${BLU}[INFO]${NC}     $1"
    echo "- INFO: $1" >> "$REPORT_FILE"
}

# Init report
echo "# OrderBuddy Malware Infection Check" > "$REPORT_FILE"
echo "**Datum:** $(date)" >> "$REPORT_FILE"
echo "**Host:** $(hostname)" >> "$REPORT_FILE"
echo "**User:** $(whoami)" >> "$REPORT_FILE"
echo "**OS:** $(uname -srm)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  ORDERBUDDY MALWARE — INFEKTIONSPRÜFUNG                 ║${NC}"
echo -e "${BOLD}║  Dieses Script liest nur. Nichts wird verändert.        ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Host:     $(hostname)"
echo -e "  User:     $(whoami)"
echo -e "  Home:     $HOME"
echo -e "  OS:       $(uname -srm)"
echo -e "  Datum:    $(date)"

# ================================================================
# CHECK 1: Malware-Artefakte im .vscode Ordner
# ================================================================
log_header "1. Malware-Artefakte im ~/.vscode/"

if [ -f "$HOME/.vscode/test.js" ]; then
    log_critical "~/.vscode/test.js EXISTIERT — Stage-2 Payload wurde heruntergeladen!"
    log_info "  SHA256: $(sha256_hash "$HOME/.vscode/test.js")"
    log_info "  Größe: $(wc -c < "$HOME/.vscode/test.js" 2>/dev/null) bytes"
    log_info "  Erstellt: $(file_mtime "$HOME/.vscode/test.js")"
    log_info "  Erste Zeilen:"
    head -5 "$HOME/.vscode/test.js" 2>/dev/null | while read -r line; do
        log_info "    $line"
    done
else
    log_ok "~/.vscode/test.js existiert nicht"
fi

if [ -f "$HOME/.vscode/package.json" ]; then
    log_critical "~/.vscode/package.json EXISTIERT — Malware-Dependencies konfiguriert!"
    log_info "  Inhalt:"
    cat "$HOME/.vscode/package.json" 2>/dev/null | while read -r line; do
        log_info "    $line"
    done
else
    log_ok "~/.vscode/package.json existiert nicht"
fi

if [ -d "$HOME/.vscode/node_modules" ]; then
    log_critical "~/.vscode/node_modules/ EXISTIERT — Malware-Dependencies wurden installiert!"
    log_info "  Anzahl Pakete: $(ls -1 "$HOME/.vscode/node_modules/" 2>/dev/null | wc -l)"
    log_info "  Gesamtgröße: $(du -sh "$HOME/.vscode/node_modules/" 2>/dev/null | cut -f1)"
    log_info "  Erstellt: $(file_mtime "$HOME/.vscode/node_modules")"
else
    log_ok "~/.vscode/node_modules/ existiert nicht"
fi

# Prüfe auch alternative Pfade
for alt_path in "$HOME/j" "$HOME/.j" "$HOME/p" "$HOME/.p"; do
    if [ -d "$alt_path" ] || [ -f "$alt_path" ]; then
        log_warning "$alt_path existiert — möglicher Malware-Pfad"
    fi
done

# ================================================================
# CHECK 2: VS Code / Cursor Workspace History
# ================================================================
log_header "2. VS Code / Cursor Workspace-History"

check_workspace_history() {
    local app_name="$1"
    local support_dir="$2"
    
    if [ ! -d "$support_dir" ]; then
        log_info "$app_name: Support-Verzeichnis nicht gefunden ($support_dir)"
        return
    fi
    
    local found=0
    local ws_dir="$support_dir/User/workspaceStorage"
    if [ -d "$ws_dir" ]; then
        local result
        result=$(timeout 10 grep -rl "orderbuddy" "$ws_dir" 2>/dev/null | head -5)
        if [ -n "$result" ]; then
            log_critical "$app_name hat orderbuddy-main Ordner geöffnet!"
            echo "$result" | while read -r match; do
                log_info "  $match"
            done
            found=1
        fi
    fi
    
    local recent_file="$support_dir/User/globalStorage/storage.json"
    if [ -f "$recent_file" ] && grep -q "orderbuddy" "$recent_file" 2>/dev/null; then
        log_critical "$app_name: orderbuddy in recent workspaces (storage.json)!"
        found=1
    fi
    
    if [ "$found" -eq 0 ]; then
        log_ok "$app_name: Kein orderbuddy-Workspace in History gefunden"
    fi
}

# macOS
if [ "$(uname)" = "Darwin" ]; then
    check_workspace_history "VS Code" "$HOME/Library/Application Support/Code"
    check_workspace_history "Cursor" "$HOME/Library/Application Support/Cursor"
# Linux    
else
    check_workspace_history "VS Code" "$HOME/.config/Code"
    check_workspace_history "Cursor" "$HOME/.config/Cursor"
fi

# ================================================================
# CHECK 3: Laufende verdächtige Prozesse
# ================================================================
log_header "3. Laufende Prozesse"

# Node.js Prozesse die test.js oder .vscode ausführen
suspicious_procs=$(ps aux 2>/dev/null | grep -E "(node.*test\.js|node.*\.vscode|npm.*\.vscode|npm.*--prefix.*\.vscode)" | grep -v grep)
if [ -n "$suspicious_procs" ]; then
    log_critical "Verdächtige Node.js-Prozesse gefunden!"
    echo "$suspicious_procs" | while read -r proc; do
        log_info "  $proc"
    done
else
    log_ok "Keine verdächtigen Node.js-Prozesse aktiv"
fi

# Prozesse die C2-IPs kontaktieren
suspicious_net_procs=$(ps aux 2>/dev/null | grep -E "(147\.124\.202\.225|38\.92\.47\.157|gurucooldown|alanservice|jsonkeeper)" | grep -v grep)
if [ -n "$suspicious_net_procs" ]; then
    log_critical "Prozesse mit C2-Verbindung gefunden!"
    echo "$suspicious_net_procs" | while read -r proc; do
        log_info "  $proc"
    done
else
    log_ok "Keine Prozesse mit bekannten C2-Verbindungen"
fi

# ================================================================
# CHECK 4: Netzwerkverbindungen
# ================================================================
log_header "4. Aktive Netzwerkverbindungen zu C2-Servern"

C2_IPS=("147.124.202.225" "38.92.47.157" "4.202.147.122")
C2_PORT="1244"

for ip in "${C2_IPS[@]}"; do
    connections=$(netstat -an 2>/dev/null | grep "$ip" || ss -an 2>/dev/null | grep "$ip")
    if [ -n "$connections" ]; then
        log_critical "AKTIVE VERBINDUNG zu C2-Server $ip!"
        echo "$connections" | while read -r conn; do
            log_info "  $conn"
        done
    else
        log_ok "Keine Verbindung zu $ip"
    fi
done

# lsof check für Netzwerkverbindungen
for ip in "${C2_IPS[@]}"; do
    lsof_result=$(lsof -i "@$ip" 2>/dev/null)
    if [ -n "$lsof_result" ]; then
        log_critical "lsof zeigt offene Verbindung zu $ip!"
        echo "$lsof_result" | while read -r line; do
            log_info "  $line"
        done
    fi
done

# Port 1244 Verbindungen
port_conns=$(netstat -an 2>/dev/null | grep ":1244" || ss -an 2>/dev/null | grep ":1244")
if [ -n "$port_conns" ]; then
    log_warning "Verbindungen auf Port 1244 gefunden"
    echo "$port_conns" | while read -r conn; do
        log_info "  $conn"
    done
else
    log_ok "Keine Verbindungen auf Port 1244"
fi

# ================================================================
# CHECK 5: DNS-Cache / Resolve-History
# ================================================================
log_header "5. DNS-Auflösungen bekannter Malware-Domains"

MALWARE_DOMAINS=("gurucooldown.short.gy" "alanservice.vercel.app" "jsonkeeper.com" "www.jsonkeeper.com")

for domain in "${MALWARE_DOMAINS[@]}"; do
    if [ "$(uname)" = "Darwin" ]; then
        dns_result=$(timeout 15 log show --predicate "process == \"mDNSResponder\" AND eventMessage CONTAINS \"$domain\"" --style syslog --last 7d 2>/dev/null | head -3)
    else
        dns_result=$(timeout 10 journalctl -u systemd-resolved --since "7 days ago" --no-pager 2>/dev/null | grep -i "$domain" | head -3)
    fi
    
    if [ -n "$dns_result" ]; then
        log_critical "DNS-Auflösung für $domain in den letzten 7 Tagen!"
        echo "$dns_result" | while read -r line; do
            log_info "  $line"
        done
    else
        log_ok "Keine DNS-Auflösung für $domain gefunden"
    fi
done

# ================================================================
# CHECK 6: Shell-History
# ================================================================
log_header "6. Shell-History"

HISTORY_FILES=("$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.fish_history" "$HOME/.history")

for hfile in "${HISTORY_FILES[@]}"; do
    if [ -f "$hfile" ]; then
        log_info "Prüfe $hfile..."
        
        # Suche nach Malware-bezogenen Befehlen
        suspicious_cmds=$(grep -n -i -E "(orderbuddy|gurucooldown|alanservice|jsonkeeper|147\.124\.202\.225|38\.92\.47\.157|4\.202\.147\.122|npm.*install.*\.vscode|node.*test\.js.*\.vscode|curl.*short\.gy|wget.*short\.gy)" "$hfile" 2>/dev/null)
        
        if [ -n "$suspicious_cmds" ]; then
            log_critical "Verdächtige Befehle in $hfile gefunden!"
            echo "$suspicious_cmds" | while read -r cmd; do
                log_info "  $cmd"
            done
        else
            log_ok "Keine verdächtigen Befehle in $hfile"
        fi
        
        # Suche nach npm install/build im orderbuddy context
        npm_cmds=$(grep -n -E "(npm (run |)(build|start|install|dev)|webpack)" "$hfile" 2>/dev/null | grep -i "orderbuddy\|api\b" | head -10)
        if [ -n "$npm_cmds" ]; then
            log_warning "npm build/install Befehle die orderbuddy betreffen könnten:"
            echo "$npm_cmds" | while read -r cmd; do
                log_info "  $cmd"
            done
        fi
    fi
done

# ================================================================
# CHECK 7: npm Cache & global installs
# ================================================================
log_header "7. npm Cache & Global Packages"

# npm cache log für Malware-Dependencies
if [ -d "$HOME/.npm/_logs" ]; then
    npm_logs=$(grep -rl "\.vscode" "$HOME/.npm/_logs/" 2>/dev/null | head -5)
    if [ -n "$npm_logs" ]; then
        log_warning "npm Logs referenzieren .vscode Installationen:"
        echo "$npm_logs" | while read -r logf; do
            log_info "  $logf"
            grep "\.vscode" "$logf" 2>/dev/null | head -3 | while read -r line; do
                log_info "    $line"
            done
        done
    else
        log_ok "Keine npm Logs mit .vscode Referenzen"
    fi
fi

# npm cache für verdächtige Pakete
if command -v npm &>/dev/null; then
    npm_cache_ls=$(npm cache ls 2>/dev/null | grep -i "test\|malware\|exfil\|keylog\|steal" | head -5)
    if [ -n "$npm_cache_ls" ]; then
        log_warning "Verdächtige Pakete im npm Cache"
    fi
fi

# ================================================================
# CHECK 8: Browser-History (IOC URLs)
# ================================================================
log_header "8. Browser-History (IOC URLs)"

check_browser_db() {
    local name="$1"
    local db_path="$2"
    
    if [ ! -f "$db_path" ]; then
        log_info "$name: DB nicht gefunden"
        return
    fi
    
    for url_pattern in "gurucooldown" "alanservice" "jsonkeeper" "147.124.202" "38.92.47" "orderbuddy"; do
        result=$(sqlite3 "$db_path" "SELECT url, datetime(last_visit_time/1000000-11644473600, 'unixepoch') FROM urls WHERE url LIKE '%${url_pattern}%' LIMIT 5;" 2>/dev/null)
        if [ -n "$result" ]; then
            log_warning "$name: IOC-URL '$url_pattern' in Browser-History!"
            echo "$result" | while read -r row; do
                log_info "  $row"
            done
        fi
    done
}

# Chrome
if [ "$(uname)" = "Darwin" ]; then
    check_browser_db "Chrome" "$HOME/Library/Application Support/Google/Chrome/Default/History"
    check_browser_db "Brave" "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default/History"
    check_browser_db "Edge" "$HOME/Library/Application Support/Microsoft Edge/Default/History"
    
    # Safari (different format)
    if [ -f "$HOME/Library/Safari/History.db" ]; then
        safari_result=$(sqlite3 "$HOME/Library/Safari/History.db" "SELECT url FROM history_items WHERE url LIKE '%gurucooldown%' OR url LIKE '%alanservice%' OR url LIKE '%jsonkeeper%' LIMIT 5;" 2>/dev/null)
        if [ -n "$safari_result" ]; then
            log_warning "Safari: IOC-URLs in History!"
            echo "$safari_result" | while read -r row; do
                log_info "  $row"
            done
        fi
    fi
else
    check_browser_db "Chrome" "$HOME/.config/google-chrome/Default/History"
    check_browser_db "Brave" "$HOME/.config/BraveSoftware/Brave-Browser/Default/History"
    check_browser_db "Firefox" "$HOME/.mozilla/firefox/*.default-release/places.sqlite"
fi

# ================================================================
# CHECK 9: Persistence-Mechanismen
# ================================================================
log_header "9. Persistence-Mechanismen"

# macOS Launch Agents/Daemons
if [ "$(uname)" = "Darwin" ]; then
    for plist_dir in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
        if [ -d "$plist_dir" ]; then
            suspicious_plists=$(grep -rl -E "(orderbuddy|test\.js|\.vscode.*node|147\.124|38\.92\.47|gurucooldown)" "$plist_dir/" 2>/dev/null)
            if [ -n "$suspicious_plists" ]; then
                log_critical "Verdächtige Launch Agents/Daemons gefunden!"
                echo "$suspicious_plists" | while read -r p; do
                    log_info "  $p"
                    cat "$p" 2>/dev/null | while read -r line; do
                        log_info "    $line"
                    done
                done
            fi
        fi
    done
    log_ok "Keine verdächtigen Launch Agents/Daemons" 2>/dev/null
    
    # Login Items
    log_info "Login Items prüfen..."
    osascript -e 'tell application "System Events" to get name of every login item' 2>/dev/null | while read -r items; do
        if echo "$items" | grep -qi "orderbuddy\|test\.js\|node"; then
            log_warning "Verdächtiges Login Item: $items"
        fi
    done
else
    # Linux: crontab, systemd
    cron_result=$(crontab -l 2>/dev/null | grep -E "(orderbuddy|test\.js|\.vscode.*node|147\.124|38\.92\.47)")
    if [ -n "$cron_result" ]; then
        log_critical "Verdächtige Crontab-Einträge!"
        echo "$cron_result" | while read -r line; do
            log_info "  $line"
        done
    else
        log_ok "Keine verdächtigen Crontab-Einträge"
    fi
    
    # Systemd user services
    suspicious_services=$(grep -rl -E "(orderbuddy|test\.js|\.vscode.*node)" "$HOME/.config/systemd/user/" 2>/dev/null)
    if [ -n "$suspicious_services" ]; then
        log_critical "Verdächtige systemd User-Services!"
        echo "$suspicious_services" | while read -r svc; do
            log_info "  $svc"
        done
    else
        log_ok "Keine verdächtigen systemd User-Services"
    fi
fi

# ================================================================
# CHECK 10: SSH Keys & Credentials Timestamps
# ================================================================
log_header "10. SSH Keys & Credential-Dateien"

if [ -d "$HOME/.ssh" ]; then
    log_info "SSH-Verzeichnis Timestamps:"
    ls -la "$HOME/.ssh/" 2>/dev/null | while read -r line; do
        log_info "  $line"
    done
    
    # Prüfe ob authorized_keys kürzlich geändert wurde
    if [ -f "$HOME/.ssh/authorized_keys" ]; then
        mod_time=$(file_mtime "$HOME/.ssh/authorized_keys")
        log_info "authorized_keys zuletzt geändert: $mod_time"
        recent=$(find "$HOME/.ssh/authorized_keys" -mtime -7 2>/dev/null)
        if [ -n "$recent" ]; then
            log_warning "authorized_keys wurde in den letzten 7 Tagen geändert!"
        fi
    fi
fi

# Prüfe ob .env Dateien kürzlich gelesen wurden (atime)
log_info "Kürzlich zugegriffene sensible Dateien:"
find "$HOME" -maxdepth 3 \( -name ".env*" -o -name "*.pem" -o -name "*.key" -o -name "credentials*" \) -type f 2>/dev/null | head -20 | while read -r f; do
    if [ "$(uname)" = "Darwin" ]; then
        mod=$(stat -f "%Sm" "$f" 2>/dev/null)
    else
        mod=$(date -r "$f" "+%Y-%m-%d %H:%M:%S" 2>/dev/null)
    fi
    log_info "  $f ($mod)"
done

# ================================================================
# CHECK 11: Kürzlich modifizierte Dateien im Home
# ================================================================
log_header "11. Kürzlich erstellte verdächtige Dateien"

log_info "Dateien in den letzten 48h erstellt/modifiziert (Home):"
find "$HOME" -maxdepth 4 -type f \( -name "test.js" -o -name "*.sh" -o -name "payload*" -o -name "*.ps1" \) -mtime -2 2>/dev/null | grep -v node_modules | grep -v ".Trash" | head -20 | while read -r f; do
    log_warning "Kürzlich modifiziert: $f"
done

# Suche nach verdächtigen Dateien überall
for suspicious_file in "test.js" "payload.js" "exfil.js" "keylog.js" "stealer.js"; do
    found=$(find "$HOME" -maxdepth 5 -name "$suspicious_file" -not -path "*/node_modules/*" -not -path "*/.Trash/*" 2>/dev/null)
    if [ -n "$found" ]; then
        echo "$found" | while read -r f; do
            log_warning "Verdächtige Datei: $f ($(wc -c < "$f" 2>/dev/null) bytes)"
        done
    fi
done

# ================================================================
# CHECK 12: Firewall / Little Snitch Logs (macOS)
# ================================================================
log_header "12. Firewall & Netzwerk-Logs"

if [ "$(uname)" = "Darwin" ]; then
    # macOS Unified Log — Netzwerkverbindungen
    log_info "Suche in macOS Unified Logs (letzte 7 Tage)..."
    for search_term in "147.124.202.225" "38.92.47.157" "gurucooldown" "alanservice.vercel" "jsonkeeper"; do
        result=$(timeout 15 log show --predicate "eventMessage CONTAINS '$search_term'" --style syslog --last 7d 2>/dev/null | head -5)
        if [ -n "$result" ]; then
            log_critical "Netzwerk-Log-Eintrag für '$search_term'!"
            echo "$result" | while read -r line; do
                log_info "  $line"
            done
        fi
    done
    
    if [ -d "/Library/Little Snitch" ] || [ -d "$HOME/Library/Application Support/Little Snitch" ]; then
        log_info "Little Snitch ist installiert — prüfe Regeln..."
        ls_logs=$(find "$HOME/Library/Application Support/Little Snitch" -name "*.log" -mtime -7 2>/dev/null)
        if [ -n "$ls_logs" ]; then
            for logf in $ls_logs; do
                grep -l -E "(147\.124|38\.92|gurucooldown|alanservice)" "$logf" 2>/dev/null && log_critical "Little Snitch hat C2-Verbindung geloggt: $logf"
            done
        fi
    fi
else
    log_info "Suche in System-Logs..."
    for search_term in "147.124.202.225" "38.92.47.157" "gurucooldown" "alanservice"; do
        result=$(timeout 10 journalctl --since "7 days ago" --no-pager 2>/dev/null | grep "$search_term" | head -5)
        if [ -n "$result" ]; then
            log_critical "System-Log-Eintrag für '$search_term'!"
            echo "$result" | while read -r line; do
                log_info "  $line"
            done
        fi
    done
    
    # UFW logs
    if [ -f "/var/log/ufw.log" ]; then
        ufw_hits=$(grep -E "(147\.124\.202\.225|38\.92\.47\.157)" /var/log/ufw.log 2>/dev/null | head -5)
        if [ -n "$ufw_hits" ]; then
            log_critical "UFW hat C2-Verbindung geloggt!"
            echo "$ufw_hits" | while read -r line; do
                log_info "  $line"
            done
        fi
    fi
fi

# ================================================================
# CHECK 13: node / npm Prozess-Spuren
# ================================================================
log_header "13. Node.js Prozess-Spuren"

# /tmp Artefakte
log_info "Prüfe /tmp auf Node.js Artefakte..."
tmp_node=$(find /tmp -maxdepth 2 -name "*.js" -o -name "node*" -o -name "npm*" 2>/dev/null | head -10)
if [ -n "$tmp_node" ]; then
    echo "$tmp_node" | while read -r f; do
        if grep -ql -E "(147\.124|38\.92|gurucooldown|alanservice|jsonkeeper)" "$f" 2>/dev/null; then
            log_critical "C2-Referenz in temp Datei: $f"
        fi
    done
fi

# npm debug logs
log_info "Prüfe npm Debug-Logs..."
find "$HOME" -maxdepth 3 -name "npm-debug.log*" -mtime -7 2>/dev/null | while read -r logf; do
    if grep -ql "\.vscode" "$logf" 2>/dev/null; then
        log_warning "npm Debug-Log referenziert .vscode: $logf"
    fi
done

# ================================================================
# CHECK 14: Cursor / Claude API Logs
# ================================================================
log_header "14. Cursor / Claude Interaction Logs"

# Prüfe ob Cursor das Repo geöffnet hat
if [ "$(uname)" = "Darwin" ]; then
    cursor_storage="$HOME/Library/Application Support/Cursor"
else
    cursor_storage="$HOME/.config/Cursor"
fi

if [ -d "$cursor_storage" ]; then
    cursor_refs=$(timeout 10 grep -rl "orderbuddy" "$cursor_storage/User/workspaceStorage/" 2>/dev/null | head -5)
    if [ -n "$cursor_refs" ]; then
        log_critical "Cursor hat orderbuddy-main als Workspace geöffnet!"
        echo "$cursor_refs" | while read -r ref; do
            log_info "  $ref"
        done
    else
        log_ok "Kein orderbuddy-Workspace in Cursor-Storage"
    fi
    
    cursor_task_log=$(timeout 10 grep -rl -E "(gurucooldown|folderOpen.*runOn)" "$cursor_storage/" 2>/dev/null | head -5)
    if [ -n "$cursor_task_log" ]; then
        log_warning "Cursor-Logs referenzieren Task-Auto-Execute!"
        echo "$cursor_task_log" | while read -r ref; do
            log_info "  $ref"
        done
    fi
fi

# Gleiche Prüfung für VS Code
if [ "$(uname)" = "Darwin" ]; then
    vscode_storage="$HOME/Library/Application Support/Code"
else
    vscode_storage="$HOME/.config/Code"
fi

if [ -d "$vscode_storage" ]; then
    vscode_refs=$(timeout 10 grep -rl "orderbuddy" "$vscode_storage/User/workspaceStorage/" 2>/dev/null | head -5)
    if [ -n "$vscode_refs" ]; then
        log_critical "VS Code hat orderbuddy-main als Workspace geöffnet!"
        echo "$vscode_refs" | while read -r ref; do
            log_info "  $ref"
        done
    else
        log_ok "Kein orderbuddy-Workspace in VS Code Storage"
    fi
fi

# ================================================================
# CHECK 15: orderbuddy-main Ordner selbst
# ================================================================
log_header "15. orderbuddy-main Repo auf dem System"

orderbuddy_locations=$(timeout 15 find "$HOME" -maxdepth 5 -type d -name "orderbuddy*" -not -path "*/node_modules/*" -not -path "*/.Trash/*" 2>/dev/null | head -10)
if [ -n "$orderbuddy_locations" ]; then
    echo "$orderbuddy_locations" | while read -r loc; do
        log_warning "orderbuddy Ordner gefunden: $loc"
        
        # Prüfe ob npm install ausgeführt wurde
        if [ -d "$loc/node_modules" ] || [ -d "$loc/src/api/node_modules" ]; then
            log_critical "npm install wurde in $loc ausgeführt! Malware könnte aktiv sein!"
        fi
        
        # Prüfe ob build ausgeführt wurde
        if [ -d "$loc/src/api/dist" ] || [ -d "$loc/dist" ]; then
            log_critical "Build wurde ausgeführt in $loc! webpack-Payload könnte getriggert sein!"
        fi
        
        # Prüfe ob .vscode/tasks.json vorhanden (auto-execute)
        if [ -f "$loc/.vscode/tasks.json" ]; then
            log_warning "tasks.json vorhanden in $loc/.vscode/ — Auto-Execute möglich"
        fi
    done
else
    log_ok "Kein orderbuddy Ordner auf dem System gefunden"
fi

# ================================================================
# CHECK 16: macOS-spezifisch: Quarantine, Downloads, TCC
# ================================================================
log_header "16. macOS-spezifische Checks"

if [ "$(uname)" = "Darwin" ]; then
    # Gatekeeper Quarantine: zeigt ob ZIP heruntergeladen wurde
    log_info "Prüfe Downloads-Ordner auf orderbuddy..."
    downloads_hit=$(find "$HOME/Downloads" -maxdepth 2 -iname "*orderbuddy*" 2>/dev/null)
    if [ -n "$downloads_hit" ]; then
        log_warning "orderbuddy-Datei im Downloads-Ordner!"
        echo "$downloads_hit" | while read -r dl; do
            log_info "  $dl"
            # Quarantine-Attribut zeigt den Download-Ursprung
            qattr=$(xattr -p com.apple.quarantine "$dl" 2>/dev/null)
            if [ -n "$qattr" ]; then
                log_info "  Quarantine-Flag: $qattr"
            fi
        done
    else
        log_ok "Kein orderbuddy im Downloads-Ordner"
    fi
    
    # Prüfe ob curl/wget kürzlich ausgeführt wurden (TCC logs)
    log_info "Prüfe macOS Security-Logs für Netzwerkzugriffe..."
    for app_term in "curl" "wget" "node"; do
        tcc_result=$(timeout 10 log show --predicate "process == \"$app_term\"" --style syslog --last 48h 2>/dev/null | grep -iE "(gurucooldown|alanservice|jsonkeeper|147\.124|38\.92)" | head -3)
        if [ -n "$tcc_result" ]; then
            log_critical "macOS Log: $app_term hat C2/Malware-URL kontaktiert!"
            echo "$tcc_result" | while read -r line; do
                log_info "  $line"
            done
        fi
    done
    
    # Prüfe Keychain-Zugriffe (falls Malware Credentials auslesen wollte)
    log_info "Prüfe Keychain-Zugriffe in letzten 48h..."
    keychain_access=$(timeout 10 log show --predicate 'subsystem == "com.apple.securityd"' --style syslog --last 48h 2>/dev/null | grep -i "node\|npm\|orderbuddy" | head -5)
    if [ -n "$keychain_access" ]; then
        log_warning "Node.js/npm hat auf Keychain zugegriffen!"
        echo "$keychain_access" | while read -r line; do
            log_info "  $line"
        done
    else
        log_ok "Keine verdächtigen Keychain-Zugriffe durch Node.js"
    fi
    
    # Prüfe Accessibility/TCC Permissions
    log_info "Prüfe TCC-Datenbank auf verdächtige Berechtigungen..."
    if [ -f "$HOME/Library/Application Support/com.apple.TCC/TCC.db" ]; then
        tcc_node=$(sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
            "SELECT client, service, auth_value FROM access WHERE client LIKE '%node%' OR client LIKE '%npm%' OR client LIKE '%cursor%';" 2>/dev/null)
        if [ -n "$tcc_node" ]; then
            log_info "TCC-Berechtigungen für Node/Cursor:"
            echo "$tcc_node" | while read -r line; do
                log_info "  $line"
            done
        fi
    fi
else
    log_info "Nicht macOS — macOS-spezifische Checks übersprungen"
fi

# ================================================================
# CHECK 17: Netzwerk-Statistik
# ================================================================
log_header "17. Netzwerk-Statistik (established connections)"

log_info "Aktuelle ausgehende Verbindungen:"
if command -v netstat &>/dev/null; then
    netstat -an 2>/dev/null | grep ESTABLISHED | grep -v "127.0.0.1\|::1" | sort | uniq -c | sort -rn | head -20 | while read -r line; do
        # Prüfe ob eine der IPs zu den C2s gehört
        if echo "$line" | grep -qE "(147\.124\.202|38\.92\.47|1244)"; then
            log_critical "C2-Verbindung aktiv: $line"
        else
            log_info "  $line"
        fi
    done
elif command -v ss &>/dev/null; then
    ss -tn state established 2>/dev/null | grep -v "127.0.0.1\|::1" | head -20 | while read -r line; do
        if echo "$line" | grep -qE "(147\.124\.202|38\.92\.47|1244)"; then
            log_critical "C2-Verbindung aktiv: $line"
        else
            log_info "  $line"
        fi
    done
fi

# ================================================================
# ZUSAMMENFASSUNG
# ================================================================
log_header "ZUSAMMENFASSUNG (17 Checks)"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
if [ "$INFECTED" -gt 0 ]; then
    echo -e "${BOLD}║  ${RED}ERGEBNIS: INFEKTION GEFUNDEN${NC}${BOLD}                            ║${NC}"
else
    if [ "$SUSPICIOUS" -gt 0 ]; then
        echo -e "${BOLD}║  ${YEL}ERGEBNIS: VERDÄCHTIGE SPUREN${NC}${BOLD}                            ║${NC}"
    else
        echo -e "${BOLD}║  ${GRN}ERGEBNIS: KEINE INFEKTION ERKANNT${NC}${BOLD}                       ║${NC}"
    fi
fi
echo -e "${BOLD}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║${NC}  Kritische Findings:  ${RED}$INFECTED${NC}"
echo -e "${BOLD}║${NC}  Warnungen:           ${YEL}$SUSPICIOUS${NC}"
echo -e "${BOLD}║${NC}  OK-Checks:           ${GRN}$CLEAN_CHECKS${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════╣${NC}"

if [ "$INFECTED" -gt 0 ]; then
    echo -e "${BOLD}║${NC}  ${RED}SOFORTIGE MASSNAHMEN:${NC}"
    echo -e "${BOLD}║${NC}  1. Netzwerk SOFORT trennen"
    echo -e "${BOLD}║${NC}  2. Verdächtige Prozesse killen:"
    echo -e "${BOLD}║${NC}     pkill -f 'node.*test.js'"
    echo -e "${BOLD}║${NC}     pkill -f 'node.*.vscode'"
    echo -e "${BOLD}║${NC}  3. Malware-Artefakte sichern (forensisch):"
    echo -e "${BOLD}║${NC}     tar czf ~/malware_evidence.tar.gz \\"
    echo -e "${BOLD}║${NC}       ~/.vscode/test.js ~/.vscode/package.json \\"
    echo -e "${BOLD}║${NC}       ~/.vscode/node_modules/ 2>/dev/null"
    echo -e "${BOLD}║${NC}  4. ALLE Credentials rotieren"
    echo -e "${BOLD}║${NC}  5. System neu aufsetzen"
fi

echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Report gespeichert: ${BOLD}$REPORT_FILE${NC}"
echo ""

# Report footer
echo "" >> "$REPORT_FILE"
echo "---" >> "$REPORT_FILE"
echo "## Ergebnis" >> "$REPORT_FILE"
echo "- Kritische Findings: $INFECTED" >> "$REPORT_FILE"
echo "- Warnungen: $SUSPICIOUS" >> "$REPORT_FILE"
echo "- OK-Checks: $CLEAN_CHECKS" >> "$REPORT_FILE"

if [ "$INFECTED" -gt 0 ]; then
    exit 1
elif [ "$SUSPICIOUS" -gt 0 ]; then
    exit 2
else
    exit 0
fi
