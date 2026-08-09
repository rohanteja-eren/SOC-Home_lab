# Wazuh Lab Setup: Manager Deployment & Agent Onboarding

## Overview

This is the foundational setup behind all of the detection PoCs in this repository. It documents standing up the Wazuh manager, onboarding a Windows 10 endpoint as an agent, and installing Sysmon so the endpoint produces the process and network telemetry the later detection exercises (RDP brute force, Mimikatz, and so on) depend on.

This is not a detection PoC on its own: it is not ranked by severity like the other folders: but it is included because every other PoC in this repo builds on this environment.

## Lab Environment

| Machine | Role | Operating System | Purpose |
|---|---|---|---|
| rohan-VMware-Virtual-Platform | Wazuh Manager | Ubuntu 64-bit (Docker, single-node) | Runs the wazuh-indexer, wazuh-manager, and wazuh-dashboard containers |
| DESKTOP-TDOGRJA | Agent / Endpoint | Windows 10 Pro 10.0.19045.3803 | Wazuh agent plus Sysmon (SwiftOnSecurity config) |

## Objective

Deploy a working Wazuh manager, onboard a Windows endpoint as an agent, and install Sysmon so the rest of the lab's detection exercises have the telemetry pipeline they need.

## Setup Steps

### 1. Deploying the Wazuh Manager

The manager runs as a single-node Docker deployment on Ubuntu, using the official wazuh-docker single-node compose file. Bringing the stack up starts three containers in sequence: wazuh-indexer first, then wazuh-manager and wazuh-dashboard. Once the indexer reports a green cluster and the dashboard container is up, the web interface becomes reachable at the manager's IP over HTTPS.

### 2. Initial Dashboard (No Agents)

Before any agent was deployed, the dashboard's Agents Summary showed nothing registered, and the 24-hour alert counts reflected only the manager's own internal activity: 45 medium and 142 low severity events, nothing critical or high.

### 3. Deploying the Windows Agent

The dashboard's "Deploy new agent" wizard generated the install command for the selected OS and group. For the Windows 10 endpoint, group Default, it produced a PowerShell one-liner that downloads the MSI and installs it silently with the manager address and agent name baked in:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.6-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='192.168.142.130' WAZUH_AGENT_NAME='victim'
```

Run as Administrator in a PowerShell terminal on the Windows endpoint, this downloaded and installed the agent.

### 4. Verifying the Agent

With the service running against the correct manager address, the endpoint showed up in the dashboard as an active agent within seconds.

| Field | Value |
|---|---|
| Agent ID | 001 |
| Status | active |
| IP address | 192.168.142.130 |
| Agent version | Wazuh v4.14.6 |
| Operating system | Microsoft Windows 10 Pro 10.0.19045.3803 |
| Group | default |
| Cluster node | node01 |

### 5. Adding Sysmon (SwiftOnSecurity Config)

The default Windows Security event log covers logon/logoff and account activity but not process creation detail, parent/child relationships, or remote thread and memory access: telemetry the later detection work (Mimikatz in particular) relies on. Sysmon fills that gap and was installed on the endpoint after the agent was confirmed active.

Rather than writing a Sysmon config from scratch, this used the SwiftOnSecurity configuration, a well-known baseline that logs security-relevant event types without drowning the pipeline in noise:

```powershell
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig-export.xml
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

With Sysmon installed and logging to `Microsoft-Windows-Sysmon/Operational`, the Wazuh agent config was updated to forward that channel to the manager:

```xml
<localfile>
<location>Microsoft-Windows-Sysmon/Operational</location>
<log_format>eventchannel</log_format>
</localfile>
```

This is what later shows up as Sysmon event groups (`sysmon_event1`, `sysmon_event8`, `sysmon_event_10`) in Wazuh's ruleset: process creation, remote thread creation, and process memory access respectively.

## Troubleshooting

### Problem
Starting the agent service right after install didn't work. `ossec.log` showed the agent repeatedly failing to find a manager to talk to:

```
ERROR: (4112): Invalid server address found: '0.0.0.0'
ERROR: (1215): No client configured. Exiting.
INFO: Received exit signal. Starting exit process.
```

### Investigation
The manager address hadn't actually made it into `ossec.conf`. The service had been started against an install that predated the `WAZUH_MANAGER` variable being set correctly.

### Fix
Re-ran the documented install command with `WAZUH_MANAGER='192.168.142.130'` explicitly set, then started the service again with `NET START Wazuh`.

### Result
The agent connected successfully and showed up in the dashboard as an active agent within seconds.

## What I Learned

- Deploying Wazuh manager as a single-node Docker stack
- Windows agent installation and onboarding
- Reading `ossec.log` to diagnose agent connection failures
- Installing and configuring Sysmon (SwiftOnSecurity baseline) for enhanced telemetry
- Forwarding Windows event channels (Sysmon) to the Wazuh agent config

## Evidence

- wazuh-indexer container starting (cluster health YELLOW → GREEN)
- Wazuh dashboard overview with no agents registered
- Deploy new agent wizard / install command
- Agent MSI installing on the Windows 10 endpoint
- `ossec.log` showing the 0.0.0.0 / no client configured error
- Wazuh service starting successfully after the fix
- DESKTOP-TDOGRJA listed as an active agent in the dashboard

## Next Steps

This environment is the baseline used by the following detection PoCs in this repository:

- [`../01-File-Integrity-Monitoring/README.md`](../01-File-Integrity-Monitoring/README.md)
- [`../02-Firewall-Manipulation-Detection/README.md`](../02-Firewall-Manipulation-Detection/README.md)
- [`../03-Mimikatz-Credential-Dumping-Detection/README.md`](../03-Mimikatz-Credential-Dumping-Detection/README.md)
- [`../04-Scheduled-Task-Persistence-Detection/README.md`](../04-Scheduled-Task-Persistence-Detection/README.md)
- [`../05-RDP-Bruteforce-Detection/README.md`](../05-RDP-Bruteforce-Detection/README.md)
