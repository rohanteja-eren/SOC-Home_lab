# SOC-Home_lab

A hands-on home lab for security operations and detection engineering, built around Wazuh and Sysmon on a small Windows/Kali/Ubuntu setup. Each project simulates an attack technique, checks whether the existing detection stack caught it, and documents the custom Wazuh rule written to close the gap when it didn't.

## Contents

### [Wazuh-Detection-PoCs](Wazuh-Detection-PoCs/)

Five detection engineering PoCs plus the base lab setup, ordered from lowest to highest documented Wazuh severity:

| PoC | Technique | MITRE ID | Severity |
|---|---|---|---|
| [File Integrity Monitoring](Wazuh-Detection-PoCs/01-File-Integrity-Monitoring/README.md) | Stored Data Manipulation | T1565.001 | Level 5 |
| [Firewall Manipulation Detection](Wazuh-Detection-PoCs/02-Firewall-Manipulation-Detection/README.md) | System Network Configuration Discovery / Impair Defenses | T1016 / T1562.004 | Level 10 |
| [Mimikatz Credential Dumping Detection](Wazuh-Detection-PoCs/03-Mimikatz-Credential-Dumping-Detection/README.md) | LSASS Memory / PowerShell | T1003.001 / T1059.001 | Level 12 |
| [Scheduled Task Persistence Detection](Wazuh-Detection-PoCs/04-Scheduled-Task-Persistence-Detection/README.md) | Scheduled Task/Job | T1053.005 | Level 13 |
| [RDP Brute-Force Detection](Wazuh-Detection-PoCs/05-RDP-Bruteforce-Detection/README.md) | Brute Force | T1110 | Level 13 |

Each PoC folder has a full write-up, attack scenario, telemetry, detection logic, validation, troubleshooting, false-positive analysis, and limitations, plus the exact Wazuh rule implemented and the original source report.

## Lab Environment

- **SIEM:** Wazuh (Docker, single-node manager)
- **Endpoint telemetry:** Sysmon (SwiftOnSecurity config) on a Windows 10 target
- **Adversary emulation:** MITRE Caldera, Hydra, Mimikatz
- **Attacker platform:** Kali Linux

See [Wazuh-Detection-PoCs/00-Lab-Environment-Setup](Wazuh-Detection-PoCs/00-Lab-Environment-Setup/README.md) for how the manager, agent, and Sysmon were deployed.

