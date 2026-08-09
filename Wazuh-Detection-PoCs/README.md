# Wazuh Detection Engineering PoCs

## Overview

This repository contains hands-on Wazuh/Sysmon detection PoCs developed and validated in a controlled home lab. Each PoC simulates a specific attack technique, checks whether the existing detection stack caught it, and where it didn't, documents the custom Wazuh rule written to close the gap.

These are proof-of-concept exercises, not production-ready detections. Several of the rules are simple, filename-based, or otherwise carry documented limitations and potential false positives. Each PoC's README says so directly rather than hiding it.

## Detection Scenarios

PoCs are ordered from lowest to highest documented Wazuh severity.

| PoC | Technique | MITRE ID | Rule ID | Severity |
|---|---|---|---|---|
| [File Integrity Monitoring](01-File-Integrity-Monitoring/README.md) | Stored Data Manipulation | T1565.001 | 554 (built-in) | Level 5 |
| [Firewall Manipulation Detection](02-Firewall-Manipulation-Detection/README.md) | System Network Configuration Discovery / Impair Defenses | T1016 / T1562.004 | 100220 | Level 10 |
| [Mimikatz Credential Dumping Detection](03-Mimikatz-Credential-Dumping-Detection/README.md) | LSASS Memory / PowerShell | T1003.001 / T1059.001 | 100000, 100001, 100002 | Level 12 |
| [Scheduled Task Persistence Detection](04-Scheduled-Task-Persistence-Detection/README.md) | Scheduled Task/Job: Scheduled Task | T1053.005 | 100230 | Level 13 |
| [RDP Brute-Force Detection](05-RDP-Bruteforce-Detection/README.md) | Brute Force | T1110 | 100100, 100101 | Level 15 |

A sixth folder, [`00-Lab-Environment-Setup`](00-Lab-Environment-Setup/README.md), documents the base environment (Wazuh manager, Windows agent, Sysmon) that the five PoCs above build on. It isn't ranked by severity since it isn't a detection PoC on its own.

## Lab Architecture

```
Attacker / Simulation
        ↓
Windows Endpoint
        ↓
Sysmon
        ↓
Wazuh Agent
        ↓
Wazuh Manager
        ↓
Custom Detection Rules
        ↓
Wazuh Alerts
```

## Tools Used

- **Wazuh** (SIEM manager + agent, Docker single-node deployment)
- **Sysmon** (SwiftOnSecurity configuration)
- **MITRE Caldera** 5.3.0 (adversary emulation)
- **Mimikatz** (controlled credential-dumping simulation)
- **Hydra** (RDP brute-force simulation)
- **Kali Linux** (attacker platform)
- **Windows 10** (target endpoint)

## Detection Engineering Workflow

1. Simulate activity
2. Generate telemetry
3. Inspect logs
4. Identify detection gap
5. Create Wazuh rule
6. Test detection
7. Investigate alert
8. Analyze noise/false positives
9. Document limitations

## PoCs

- [00 - Lab Environment Setup](00-Lab-Environment-Setup/README.md)
- [01 - File Integrity Monitoring](01-File-Integrity-Monitoring/README.md)
- [02 - Firewall Manipulation Detection](02-Firewall-Manipulation-Detection/README.md)
- [03 - Mimikatz Credential Dumping Detection](03-Mimikatz-Credential-Dumping-Detection/README.md)
- [04 - Scheduled Task Persistence Detection](04-Scheduled-Task-Persistence-Detection/README.md)
- [05 - RDP Brute-Force Detection](05-RDP-Bruteforce-Detection/README.md)

Note for readers viewing this repository as a PDF export rather than on GitHub: the links above point to relative paths within the repository (for example, `01-File-Integrity-Monitoring/README.md`). They won't be clickable outside of GitHub or a live filesystem, but the paths themselves tell you exactly where to find each file.
