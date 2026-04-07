# IOC Files

Machine-readable Indicators of Compromise for the OrderBuddy campaign.

## Formats

| File | Format | Use Case |
|------|--------|----------|
| `network-iocs.csv` | CSV | SIEM import (Splunk, Elastic, QRadar) |
| `file-iocs.csv` | CSV | EDR / endpoint hash blocklists |
| `c2-endpoints.csv` | CSV | WAF / proxy rules, threat hunting queries |
| `stix2-bundle.json` | STIX 2.1 | TIP import (MISP, OpenCTI, ThreatConnect) |

## Quick Import

### Splunk

```spl
| inputlookup network-iocs.csv | where type="c2_active" OR type="c2_primary" OR type="c2_fallback"
| rename value as dest_ip
| join dest_ip [search index=firewall]
```

### Elastic / KQL

```
destination.ip: ("66.235.175.117" OR "38.92.47.157" OR "147.124.202.225" OR "4.202.147.122")
```

### MISP

Import `stix2-bundle.json` via **Sync Actions → Import from...→ STIX 2.1**.
