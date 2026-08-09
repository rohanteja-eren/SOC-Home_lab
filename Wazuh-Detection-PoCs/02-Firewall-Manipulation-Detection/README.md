# Firewall Manipulation: Detection & Response

## Overview

This PoC is a purple team exercise focused on Windows Firewall manipulation. Using MITRE Caldera as the adversary emulation platform, a firewall rule enumeration command was executed against a Windows 10 target and initially went undetected by the Wazuh SIEM. A custom detection rule was then engineered, tested, and validated, closing that gap. The same layered approach was applied to firewall *modification* activity, so legitimate administrative changes could be distinguished from suspicious ones instead of the SIEM alerting on every `netsh firewall` command.

Firewall rule enumeration and modification are security-relevant because they're both a discovery technique (mapping the host's exposed attack surface) and a defense-evasion technique (disabling or altering firewall protections to enable follow-on access, such as opening a port for a remote-access tool).

What I was trying to detect: firewall rule enumeration via `netsh advfirewall`, and firewall rule modification/creation: specifically modifications that reference ports associated with known remote-access tooling (e.g., VNC).

## Lab Environment

- Attacker platform: Kali Linux, running MITRE Caldera 5.3.0
- Target: Windows 10 host (DESKTOP-TDOGRJA)
- Detection stack: Wazuh SIEM, agent ID 001
- C2 framework: Caldera's Access plugin, used to task the agent with individual abilities outside a full operation

## Objective

The objective was to run a firewall rule enumeration technique via MITRE Caldera against a Windows endpoint, confirm whether Wazuh's default ruleset detected it, and: since it didn't: engineer and validate a custom detection rule for both the enumeration and modification sides of firewall manipulation.

## Attack / Test Scenario

1. **Initial setup**: Caldera 5.3.0 deployed on the Kali attacker platform, tasked with abilities against the Windows target via the Access plugin (rather than running a full operation).
2. **Attack execution**: The attack chain ran three abilities in sequence: Avoid Logs (defense evasion), Find Domain (discovery), and List Windows Firewall Rules (discovery, T1016), the last one run four times against the target agent. The firewall enumeration ability spawns `cmd.exe`, which in turn spawns `netsh.exe` to list all firewall rules, obfuscated with base64:
   ```
   netsh advfirewall firewall show rule name=all
   ```
3. **What happened on the victim**: Execution succeeded; the command returned the full local firewall rule set, confirming the attacker had complete visibility into the host's firewall posture.
4. **Telemetry generated**: Process creation telemetry for `cmd.exe` spawning `netsh.exe` with the enumeration arguments.
5. **How Wazuh received the telemetry**: Via the Wazuh agent on the Windows endpoint, forwarding process creation events to the manager.

### Detection Gap (Before the Custom Rule)

Before the custom rule existed, Wazuh's threat hunting view showed activity in the surrounding time window, but none of it described the firewall enumeration itself. The alerts present were unrelated: executables dropped in folders commonly used by malware, a PowerShell process spawn, and service configuration changes. The firewall rule listing happened without triggering any dedicated detection.

## Detection Logic

Two separate rule chains were built, one for each side of the firewall activity:

**Enumeration Detection**
A single correlation rule (ID 100220, severity level 10) fires when a process spawns `netsh` with `advfirewall firewall show` arguments. This is what caught the discovery step above.

**Modification Detection**
Modification detection is layered rather than a single blanket rule, since alerting on every `netsh firewall` command would be noisy in any environment where admins manage the firewall directly:

- Rule 92042 flags `netsh.exe` execution as a low-severity base event
- Rule 92043 escalates when that execution adds a firewall rule
- Rule 92044 escalates again when the added rule references local port 5900, associated with VNC

This staged approach means severity only climbs when the command pattern actually looks suspicious: first by confirming a rule was created, then by checking whether the specific port matches known remote-access tooling. Legitimate admin firewall changes and installers that create firewall exceptions during setup still generate the low-severity base event but won't escalate unless the more specific conditions are met.

## Wazuh Rule

> Complete rule XML was not included in the source report. The following rule fields and behavior **are** documented:

**Enumeration rule:**
- Rule ID: 100220
- Severity: Level 10
- Trigger condition: a process spawns `netsh` with `advfirewall firewall show` arguments
- Description (as displayed in Wazuh): "Windows Firewall Rule Enumeration Detected"

**Modification rule chain:**
- Rule 92042: `netsh.exe` execution (low-severity base event)
- Rule 92043: escalates when `netsh.exe` execution adds a firewall rule
- Rule 92044: escalates again when the added rule references local port 5900 (VNC)

## MITRE ATT&CK

| Tactic | Technique | ID |
|---|---|---|
| Defense Evasion | Indicator Removal | T1070 |
| Discovery | System Network Configuration Discovery | T1016 |
| Discovery | System Network Configuration Discovery (firewall rule listing) | T1016 |
| Defense Evasion | Impair Defenses: Disable or Modify System Firewall | T1562.004 |

## Validation

- **Attack performed:** Re-ran the "List Windows Firewall Rules" enumeration technique via Caldera after the custom rule was deployed.
- **Expected result:** Wazuh should raise a dedicated alert identifying the activity as firewall rule enumeration/discovery, rather than showing no dedicated detection as before.
- **Actual Wazuh alert:** "Windows Firewall Rule Enumeration Detected" appeared at the top of the Wazuh events view.
- **Rule ID:** 100220
- **Severity:** Level 10
- **Relevant detail:** Correctly attributed the activity to firewall rule discovery.
- **Screenshot evidence:** Yes: Caldera ability execution, tactic/technique mapping, the raw `netsh` command output, the pre-rule detection gap in threat hunting, and the post-rule alert are all referenced in the source report.

## Troubleshooting

### Problem
Wazuh's default ruleset did not detect the firewall rule enumeration technique at all: the threat hunting view showed only unrelated alerts (dropped executables, PowerShell spawns, service configuration changes) during the attack window.

### Investigation
Reviewed the threat hunting view for the attack time window and confirmed none of the existing alerts described the firewall enumeration activity specifically: it was a genuine detection gap, not a filtering or telemetry issue.

### Fix
Engineered a dedicated correlation rule (100220) that matches on `netsh` process spawns with `advfirewall firewall show` arguments.

### Result
Re-running the same enumeration technique produced a correctly attributed, level-10 alert ("Windows Firewall Rule Enumeration Detected") at the top of the Wazuh events view.

## False Positives / Noise

**Potential (documented, not directly claimed as observed):**
- Alerting on every `netsh firewall` command would be noisy in any environment where admins manage the firewall directly.
- Legitimate admin firewall changes and installers that create firewall exceptions during setup will still generate the low-severity base event (rule 92042) but are designed not to escalate unless the more specific conditions (rule creation, then VNC port match) are met.

No false positive from the enumeration rule (100220) was reported as directly observed in this report.

## Limitations

- **Lab-only validation**: tested against a single Windows 10 target in a controlled environment, not validated at scale or across diverse admin workflows.
- **Port-based escalation is narrow**: the highest-severity modification alert (92044) is scoped specifically to port 5900 (VNC); other remote-access tooling on different ports would not trigger that same escalation without additional rules.
- **Complete rule XML not available**: only rule IDs, severities, and trigger conditions are documented in the source report, not the full XML implementation.

## What I Learned

- Adversary emulation with MITRE Caldera (Access plugin, individual ability tasking)
- Identifying real detection gaps by comparing attack execution against SIEM alert output
- Detection engineering: building layered/staged correlation rules to reduce noise
- Distinguishing discovery-stage activity (enumeration) from modification-stage activity for separate detection logic
- MITRE ATT&CK mapping across multiple tactics in a single attack chain
- Validating a custom rule by re-running the same attack technique

## Evidence

- Caldera ability selection showing tactic/technique mapping before execution
- Raw `netsh advfirewall firewall show rule name=all` command output confirming full firewall rule visibility
- Wazuh threat hunting view showing the detection gap (no dedicated alert) before the custom rule
- Wazuh alert view showing "Windows Firewall Rule Enumeration Detected" (rule 100220, level 10) after the fix
