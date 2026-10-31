# Splunk SIEM Security Lab

A lab guide for collecting Windows event logs in Splunk, investigating authentication activity, and designing security dashboards.

**Repository contents:** setup guide and example scenarios. Screenshots and exported lab artifacts have not yet been added; the `screenshots/` folder currently contains a placeholder.

[Setup](#step-by-step-setup) · [Screenshots to add](#screenshots) · [Related projects](#related-projects)

## Overview

A SIEM is where security and IT teams actually live. This lab installs Splunk Enterprise (free tier, 500 MB/day) on the host PC, runs the Universal Forwarder on a Windows 10 VM, and pushes the VM's Security/System/Application event logs into Splunk. From there: detection queries, a live dashboard, and a real triggered alert during a simulated brute-force attack.

## Objectives

- Install Splunk Enterprise locally and Universal Forwarder on a target Windows 10 VM
- Ingest Windows Security, System, and Application event logs into a dedicated index
- Learn enough SPL to answer real questions about login activity
- Simulate a brute-force attack, detect it in Splunk, and write a correlation query for "compromised after multiple failures"
- Publish a 5-panel security dashboard + an automated alert

## Tools & Technologies

| Tool | Purpose |
|---|---|
| Splunk Enterprise (Free) | SIEM server |
| Splunk Universal Forwarder | Lightweight log shipper on the VM |
| Windows Event Viewer | Native source for Security/System/App logs |
| SPL (Splunk Processing Language) | Query language for log analysis |
| Windows 10 Pro VM | Target machine generating logs (from AD lab) |

## Architecture

```
   ┌─────────────────────────────┐         ┌────────────────────────────┐
   │  Windows 10 Pro VM          │         │  Host PC (Splunk Server)   │
   │                             │         │                            │
   │  Event Viewer               │         │  Splunk Enterprise         │
   │   Security  ──┐             │         │  http://localhost:8000     │
   │   System    ──┼─►  Forwarder│  9997   │                            │
   │   Application┘    (50 MB)   │ ──────► │   Receiver port 9997       │
   │                             │         │   Index: windows_logs      │
   └─────────────────────────────┘         └────────────────────────────┘
```

## Step-by-Step Setup

### Phase 1 — Install Splunk Enterprise (Server)

1. Download from splunk.com/en_us/download/splunk-enterprise.html (free trial → free tier)
2. Install via MSI as **Local System**, set admin user + password
3. Confirm `http://localhost:8000` loads, sign in

### Phase 2 — Understand Windows Event IDs

The IDs that actually matter for IT support + security work:

| Event ID | Meaning | Why It Matters |
|---|---|---|
| 4624 | Successful login | Baseline activity, audit trail |
| 4625 | Failed login attempt | Many = possible brute-force |
| 4634 | Account logged off | Session tracking |
| 4648 | Login with explicit credentials | Credential misuse signal |
| 4720 | New user account created | Watch for unauthorized creation |
| 4732 | User added to security group | Privilege escalation |
| 4740 | Account locked out | Tier-1 help desk trigger |
| 7036 | Service start/stop | System health |

### Phase 3 — Prepare Splunk to Receive Data

1. Settings → Forwarding and Receiving → **Configure receiving** → New port `9997` → Save
2. Settings → Indexes → **New Index** → name `windows_logs`

### Phase 4 — Install the Universal Forwarder on the VM

1. On the Windows 10 VM: download `splunkforwarder-*.msi` from splunk.com
2. Run installer:
   - Check **Security Event Logs**, **System Event Logs**, **Application Event Logs**
   - Deployment Server: *blank*
   - Receiving Indexer: `<HOST_PC_IP>:9997`
3. Finish. The `SplunkForwarder` service starts automatically.

### Phase 5 — Verify Ingest

In Splunk Web → Search & Reporting:

```spl
index=windows_logs
```

Events should stream in. If not:
- Both machines must be able to ping each other
- `services.msc` on VM → `SplunkForwarder` → Running

## SPL Queries (the heart of the project)

### Baseline activity
```spl
index=windows_logs earliest=-1h
```

### All failed logins
```spl
index=windows_logs EventCode=4625
```

### Failed logins grouped by account
```spl
index=windows_logs EventCode=4625
| stats count by Account_Name
| sort -count
```

### Successful logins
```spl
index=windows_logs EventCode=4624
| stats count by Account_Name, ComputerName
```

### Account lockouts
```spl
index=windows_logs EventCode=4740
| table _time, Account_Name, ComputerName
```

### Brute-force candidates (>= 5 failures)
```spl
index=windows_logs EventCode=4625
| stats count by Account_Name
| where count >= 5
| sort -count
```

### Rapid failures (1-min buckets in the last 15 min)
```spl
index=windows_logs EventCode=4625 earliest=-15m
| timechart span=1m count
```

### Correlation: failed-then-succeeded (classic post-compromise signal)
```spl
index=windows_logs (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as Failures,
        count(eval(EventCode=4624)) as Successes
        by Account_Name
| where Failures > 3 AND Successes > 0
```

## Brute-Force Simulation

Two ways to generate failed logins on the VM:

**a) Lock screen attempt:** `Ctrl+Alt+Del → Lock` → type wrong passwords 10–15 times.

**b) Command line:**
```cmd
:: run 10-15 times
net use \\localhost\IPC$ /user:FakeAttacker wrongpassword
```

Then run the "Brute-force candidates" SPL query above — `FakeAttacker` shows up with the failure count.

## Dashboard — IT Security Monitor

5 panels, all from the queries above:

| Panel | Visualization | Query basis |
|---|---|---|
| Total Failed Logins (24h) | Single Value | `EventCode=4625 \| stats count` |
| Failed Login Timeline | Line Chart | `EventCode=4625 \| timechart span=1h count` |
| Top Targeted Accounts | Bar Chart | `EventCode=4625 \| top limit=10 Account_Name` |
| Account Lockout Events | Table | `EventCode=4740 \| table _time, Account_Name, ComputerName` |
| Service Start/Stop Events | Pie Chart | `EventCode=7036 \| stats count by ComputerName` |

## Automated Alert — "Brute Force Detected"

```spl
index=windows_logs EventCode=4625
| stats count by Account_Name
| where count >= 5
```

- Save As → **Alert**
- Schedule: every 5 minutes
- Trigger: number of results > 0
- Action: Add to Triggered Alerts (or email)

## Example Investigation Log

| Incident | Event IDs | SPL Used | Finding | Response |
|---|---|---|---|---|
| Brute force attempt | 4625 | `stats count by Account_Name where count>=5` | 14 failures for `FakeAttacker` in 3 min | Alert fired; reviewed account, confirmed simulated |
| Account lockout | 4740 | `EventCode=4740` | `jdoe` locked after 5 failures | Unlocked in AD, notified user |
| Successful login post-failure | 4625 + 4624 | Correlation query (above) | Failures then success on same account | Flagged for review, password rotated |
| Service stopped | 7036 | `EventCode=7036` | `SplunkForwarder` briefly stopped on VM | Restarted service |

## Screenshots

- `01-splunk-home.png` — Splunk Web home after login
- `02-receiving-port.png` — Port 9997 receiving config
- `03-index-created.png` — `windows_logs` index in Settings
- `04-events-ingested.png` — Search showing events from VM
- `05-brute-force-query.png` — Brute-force candidate output
- `06-dashboard.png` — Full IT Security Monitor dashboard
- `07-alert-triggered.png` — Triggered Alerts page with the brute-force alert

## Learning Outcomes

- The full pipeline: source → forwarder → indexer → search → visualization
- Why correlation queries (failures **and** successes) are more valuable than single-event detections
- How SPL pipelines compose left-to-right (`search | stats | where | sort`)
- The Windows event IDs that actually matter day-to-day (4624/4625/4740/7036)
- How a scheduled alert turns a one-off investigation into ongoing monitoring
- CIA Triad concepts (Confidentiality, Integrity, Availability) applied to actual log data

## Resume wording (use after completing and verifying the lab)

> Deployed Splunk Enterprise SIEM with Universal Forwarder ingesting Windows Security/System event logs; built a 5-panel security dashboard tracking failed logins, account lockouts, and service health; simulated a brute-force attack and wrote SPL correlation queries to detect post-failure successful logins.

## Related Projects

- [Active-Directory-Home-Lab](https://github.com/deepmevada071-ui/Active-Directory-Home-Lab) — source of the Windows VM and event logs
- [Network-Troubleshooting-Lab](https://github.com/deepmevada071-ui/Network-Troubleshooting-Lab)
- [IT-HelpDesk-osTicket-Lab](https://github.com/deepmevada071-ui/IT-HelpDesk-osTicket-Lab)

---

**Deep Mevada** · Computer Science · University of Lethbridge · [deepaboutme.site](https://deepaboutme.site) · [LinkedIn](https://www.linkedin.com/in/deep-mevada-242327260/)
