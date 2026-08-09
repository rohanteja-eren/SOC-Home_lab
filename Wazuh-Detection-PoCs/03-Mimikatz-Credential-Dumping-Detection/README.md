# Mimikatz Credential Dumping Detection PoC

## Overview

This PoC evaluates Wazuh's ability to detect credential dumping with Mimikatz on a Windows endpoint. The goal was simple: run the attack, check whether the existing Sysmon and Wazuh setup caught it, and if not, build detection that does.

Credential dumping is security-relevant because tools like Mimikatz extract plaintext passwords, hashes, and other credential material directly from LSASS memory, giving an attacker the means to move laterally or escalate privileges using legitimate stolen credentials rather than exploits.

What I was trying to detect: Mimikatz execution itself, its remote thread injection into other processes, and its direct process access into a target process (Sysmon's Process Access event): the mechanism it uses to reach into LSASS.

## Lab Environment

| Machine | Role | Operating System | Purpose |
|---|---|---|---|
| DESKTOP-TDOGRJA | Target / Victim | Windows 10 Enterprise | Endpoint where Mimikatz was executed; monitored via Sysmon |
| Wazuh Manager | SIEM | Ubuntu Server | Central log correlation, custom rule matching, alerting |

## Objective

The objective was to run Mimikatz to dump credentials from LSASS memory on a monitored Windows endpoint, confirm whether Sysmon captured the right telemetry, and, since no default Wazuh rule matched the behavior, write and validate custom detection rules for it.

## Attack / Test Scenario

1. **Initial setup**: Windows 10 endpoint with Sysmon and the Wazuh agent already deployed (see [Lab Setup PoC](../00-Lab-Environment-Setup/README.md)).
2. **Attack execution**: Commands run on the victim endpoint, in order:
   ```
   cd .\mimikatz\mimikatz-master\x64
   .\mimikatz.exe
   privilege::debug
   log mimikatz.log
   sekurlsa::logonpasswords
   ```
3. **What happened on the victim**: `privilege::debug` succeeded, and `sekurlsa::logonpasswords` dumped NTLM, SHA1, and DPAPI values for the logged-on user: enough to get a crackable NTLM hash plus DPAPI keys that unlock whatever that user has saved in the browser or elsewhere on the machine.
4. **Telemetry generated**: Sysmon Event ID 1 caught the process creation cleanly: full command line, parent process, file hashes, and integrity level.
5. **How Wazuh received the telemetry**: The Wazuh agent forwarded the Sysmon event channel to the manager, where custom rules matched against it.

### Telemetry Fields Observed

| Field | Value |
|---|---|
| Image | `...\mimikatz-master\x64\mimikatz.exe` |
| ParentImage | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| IntegrityLevel | High |
| Hashes (SHA256) | `92804FAAAB2175DC501D73E814663058C78C0A042675A8937266357BCFB96C50` |

## Detection Logic

No default Wazuh rule matched Mimikatz activity, so three custom rules were added to `local_rules.xml`, all severity level 12:

- **Rule 100000**: matches Sysmon Event ID 1 (process creation) where `win.eventdata.image` contains `mimikatz.exe`.
- **Rule 100001**: matches Sysmon Event ID 8 (`sysmon_event8`, remote thread creation) where `win.eventdata.sourceImage` contains `mimikatz.exe`.
- **Rule 100002**: matches Sysmon Event ID 10 (`sysmon_event_10`, Process Access) where `win.eventdata.sourceImage` contains `mimikatz.exe`.

Rule 100000 flags process creation, 100001 flags remote thread injection, and 100002 flags direct process access (Sysmon's Process Access event) to a target process: the mechanism Mimikatz uses to reach into LSASS.

**Caveat stated directly in the source report:** these rules key off the filename `mimikatz.exe`. Renaming the binary means none of them fire.

## Wazuh Rule

```xml
<group name="windows, sysmon, sysmon_process-anomalies,">

<rule id="100000" level="12">
<if_group>sysmon_event1</if_group>
<field name="win.eventdata.image">mimikatz.exe</field>
<description>Sysmon - Suspicious Process - mimikatz.exe</description>
</rule>

<rule id="100001" level="12">
<if_group>sysmon_event8</if_group>
<field name="win.eventdata.sourceImage">mimikatz.exe</field>
<description>Sysmon - mimikatz.exe created a remote thread</description>
</rule>

<rule id="100002" level="12">
<if_group>sysmon_event_10</if_group>
<field name="win.eventdata.sourceImage">mimikatz.exe</field>
<description>Sysmon - mimikatz.exe accessed $(win.eventdata.targetImage)</description>
</rule>

</group>
```

## MITRE ATT&CK

| Tactic | Technique | ID | Notes |
|---|---|---|---|
| Execution | PowerShell | T1059.001 | `mimikatz.exe` launched from a PowerShell parent process |
| Credential Access | LSASS Memory | T1003.001 | `sekurlsa::logonpasswords` pulled NTLM, SHA1, DPAPI material |
| Privilege Escalation | Access Token Manipulation | T1134 | `privilege::debug` requested SeDebugPrivilege |
| Defense Evasion | Obfuscated Files or Information | T1027 | Unsigned binary run directly from Downloads |
| Discovery | System Information Discovery | T1082 | Session, domain, SID enumeration during auth parsing |
| Collection | Archive Collected Data | T1552.002 | `log mimikatz.log` wrote harvested credentials to disk |

## Validation

- **Attack performed:** Same Mimikatz attack re-run with the custom rules deployed.
- **Expected result:** Wazuh should correlate the Sysmon telemetry and raise an alert identifying the suspicious process.
- **Actual Wazuh alert:** Level-12 alert with full context: `rule.description` "Sysmon - Suspicious Process - mimikatz.exe", full command line and parent process captured.
- **Rule ID:** 100000 (confirmed firing); 100001 and 100002 target remote thread creation and Process Access respectively.
- **Severity:** Level 12
- **Relevant event:** Sysmon Event IDs 1, 8, and 10.
- **Dashboard filter used:** `rule.id:(100000 OR 100001 OR 100002)` under Threat Hunting: 462 correlated events, headlined by two level-12 mimikatz.exe alerts.
- **Screenshot evidence:** Yes: console output of the attack, Sysmon Event Viewer detail, the custom rules in Wazuh's Rule Manager, alert detail, and the Threat Hunting dashboard view are all referenced in the source report.

## Troubleshooting

### Problem
The Windows agent wasn't forwarding any telemetry at first.

### Investigation
The agent's log showed `"Invalid server address found: 0.0.0.0"` and `"No client configured. Exiting."`

### Fix
The manager address in the agent config was wrong; it was corrected.

### Result
The agent connected and events started showing up in Wazuh.

---

### Problem
Even after the agent connected, searching for Mimikatz activity in Threat Hunting turned up nothing useful at first.

### Investigation
Running the attack doesn't mean it gets detected automatically. The whole chain has to work end to end: Mimikatz, Windows, Sysmon, the Wazuh agent, the manager, the decoder, the rule, the alert.

### Fix
Confirmed each stage of the pipeline was actually working before assuming the rule itself was broken.

### Result
Telemetry began flowing correctly once the full pipeline was validated.

---

### Problem
The three rules target three different Sysmon event types (1, 8, 10), so it wasn't immediately clear whether a "missing" alert meant a broken rule or missing telemetry.

### Investigation
Each event type was confirmed as actually being collected before assuming any individual rule was broken.

### Fix
No rule fix needed here: this was a verification step to isolate the cause of missing alerts.

### Result
Confirmed all three event types were being received once telemetry was validated end to end.

---

### Problem
The first version of the process-creation rule didn't fire.

### Investigation
Checked the field name (`win.eventdata.image`) and event group (`sysmon_event1`) against what Wazuh was actually receiving, rather than assuming what the schema should look like.

### Fix
Corrected the field/group mismatch.

### Result
Rule 100000 fired correctly at level 12.

## False Positives / Noise

**Observed:**
- The Wazuh timeline during validation had a fair amount of routine CIS benchmark and SCA compliance events running in the background. This is unrelated baseline noise, not related to Mimikatz, and it sat at a lower severity than the level-12 mimikatz.exe alert, so the two were easy to tell apart. No false positive was observed from the custom rules during this exercise.

**Potential (documented, not observed in this exercise):**
- The rule matches on filename (`win.eventdata.image` contains `mimikatz.exe`), so it would also fire on legitimate use: an authorized pentester or admin running the actual binary. That's not a false positive observed here, but it is one the rule as written is capable of producing.

## Limitations

- **Filename-based detection**: all three rules key off the literal filename `mimikatz.exe`. Renaming the binary means none of them fire.
- **No behavioral signal**: the rules don't look at behavior independent of the filename; a production version would need host/user exclusions for authorized testing, or the filename match paired with behavioral signals instead of relying on it alone.
- **Lab-only validation**: tested in a controlled home lab against a single endpoint.

## What I Learned

- Simulating credential dumping with Mimikatz in a controlled lab
- Reading Sysmon Event IDs 1, 8, and 10 for process creation, remote thread creation, and Process Access
- Writing custom Wazuh rules keyed to specific Sysmon event groups and fields
- Debugging an end-to-end telemetry pipeline (tool → OS → Sysmon → agent → manager → decoder → rule → alert)
- Distinguishing real detections from unrelated background noise (CIS/SCA compliance events)
- Recognizing and documenting the limitations of filename-based detection
- MITRE ATT&CK mapping across execution, credential access, privilege escalation, defense evasion, discovery, and collection

## Evidence

- Console output: `privilege::debug` succeeds, `sekurlsa::logonpasswords` dumps NTLM, SHA1, and DPAPI values
- Event Viewer detail for the mimikatz.exe process creation event (Sysmon Event ID 1)
- Wazuh Rule Manager showing the custom `local_rules.xml` rules
- Alert detail: rule description "Sysmon - Suspicious Process - mimikatz.exe," full command line and parent process captured
- Wazuh Threat Hunting dashboard: 462 correlated events, headlined by two level-12 mimikatz.exe alerts
