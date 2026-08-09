# File Integrity Monitoring (FIM) PoC

## Overview

This PoC sets up File Integrity Monitoring on a Windows endpoint using Wazuh's syscheck module, then tests whether it actually caught what it should: file creates, deletes, edits, and registry changes, plus who made the change and what changed in the file itself.

File integrity monitoring is security-relevant because unauthorized file or registry changes are a common indicator of malware drops, tampering, or persistence. Detecting *that* something changed is a start; detecting *who* changed it and *what exactly* changed is what makes the alert actionable.

This PoC was trying to detect and validate: file add/delete/modify events, registry key changes, who-data attribution (user + process), and content-level diffs: using Wazuh's built-in syscheck capability rather than a hand-written custom rule.

## Lab Environment

| Machine | Role | Operating System | Purpose |
|---|---|---|---|
| Wazuh Manager | SIEM | Ubuntu Server (192.168.142.129) | Central log correlation, dashboard on port 443 |
| DESKTOP-TDOGRJA | Monitored Endpoint | Windows 10 (192.168.142.130) | Agent 001; FIM target for file and registry monitoring |
| Kali Linux | Third VM | Kali Linux | Run alongside to simulate an attacker-present network segment |

## Objective

> The objective was to configure Wazuh's syscheck module on a Windows endpoint to monitor a test directory and registry keys, confirm that file/registry changes were detected, and evaluate what additional context (compliance mapping, who-data attribution, content diffs, MITRE auto-tagging) Wazuh provides automatically.

## Attack / Test Scenario

1. **Initial setup**: Edited the Wazuh agent configuration file (`C:\Program Files (x86)\ossec-agent\ossec.conf`) to add a custom monitored directory (`C:\Users\Public\Pictures`) inside the `<syscheck>` block, dropped the scan interval to 10 seconds for testing purposes (default is 12 hours), enabled realtime monitoring on the Startup folder, and added ignore rules for noisy file types (`.log`, `.jpg`, `.png`, `.evtx`). The Wazuh agent service was restarted via PowerShell (`Restart-Service -Name wazuh`) to apply the change.
2. **Test execution**: A test file named `malware-exe` was created in the monitored folder, then renamed, edited, or deleted.
3. **What happened on the victim**: Syscheck picked up the file create/rename/edit/delete activity within the monitored directory, and also picked up registry checksum-changed events.
4. **Telemetry generated**: Syscheck (FIM) events for file-added, file-deleted, and registry-checksum-changed activity.
5. **How Wazuh received the telemetry**: The Wazuh agent on the Windows endpoint forwarded syscheck events to the Wazuh manager, viewable under Security Events > File Integrity Monitoring, filtered with `rule.groups:"syscheck" AND agent.name:"DESKTOP-TDOGRJA"`.

The file showed up on the dashboard within seconds, alongside file-deleted and registry-checksum-changed events: 40 hits for the day across file and registry activity.

### Who-Data Mode: Attribution

Scheduled and realtime mode tell you *something* changed, not *who* changed it. The test file was switched to who-data mode and edited in Notepad. The resulting alert included the user account (`Victim`), the exact process that wrote to the file (`notepad.exe`, PID 7516), and the full set of changed attributes (size, mtime, md5, sha1, sha256) with before/after values for each.

### Content Diff & MITRE Auto-Tagging

Wazuh tagged the change as MITRE ATT&CK **T1565.001 (Stored Data Manipulation)** on its own, with no manual technique lookup needed. Editing the file a second time ("testing" to "hack me") reproduced the same tag and surfaced the literal content diff (`syscheck.diff`: `< testing / > hack me`), next to the updated hashes and the file's Windows ACL permissions.

## Detection Logic

This PoC relies entirely on Wazuh's built-in syscheck module rather than a hand-written custom rule:

- **Syscheck (FIM) engine**: monitors configured directories/registry keys for create, modify, delete, and permission-change events, using checksums (md5/sha1/sha256) to detect content changes.
- **Realtime vs. scheduled vs. who-data modes**: realtime and scheduled modes report *that* a change happened; who-data mode additionally captures the responsible user account and process.
- **Built-in rule 554**: fires on file-added events (level 5).
- **Built-in rule 553**: fires on file-deleted events.
- **Automatic compliance mapping**: Wazuh attaches GDPR, HIPAA, NIST 800-53, PCI-DSS, and TSC control references to syscheck alerts automatically, without manual tagging.
- **Automatic MITRE tagging**: Wazuh auto-tagged content-modification events as T1565.001 without a manual technique lookup.

## Wazuh Rule

This PoC used Wazuh's **built-in** syscheck rules (554 for file-added, 553 for file-deleted) rather than a custom rule. No custom rule XML was written or included in the source report for this PoC: detection came from configuring syscheck itself:

```xml
<syscheck>
<directories check_all="yes" report_changes="yes" realtime="yes">C:\Users\Public\Pictures</directories>
<frequency>10</frequency>
</syscheck>
```

> Complete custom rule XML was not included in the source report: this PoC used Wazuh's built-in syscheck rules (554, 553) rather than a custom detection rule.

## MITRE ATT&CK

| Tactic | Technique | ID | Notes |
|---|---|---|---|
| Impact | Stored Data Manipulation | T1565.001 | Directly observed: auto-tagged by Wazuh when the test file's content was altered |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 | Matches the "File deleted" events (rule 553) seen during basic testing |
| Persistence | Registry Run Keys / Startup Folder | T1547.001 | Matches the monitored Startup folder and registry run-key paths |
| Defense Evasion | Modify Registry | T1112 | Matches the registry checksum-changed alerts seen throughout testing |
| Defense Evasion | Masquerading | T1036 | Matches the deliberately suspicious file name (`malware-exe`) used |

Only T1565.001 was directly auto-tagged by Wazuh during testing. The remaining techniques are documented as what FIM is broadly used to catch, included for context rather than claimed as directly observed.

## Validation

- **Test performed:** File created, renamed, edited, and deleted in the monitored directory; registry keys under monitoring also changed as part of normal Windows activity.
- **Expected result:** Wazuh should raise syscheck alerts for each add/delete/modify event with full context.
- **Actual Wazuh alert:** File-added alert for `malware-exe`, rule 554, level 5, with automatic compliance mapping attached (GDPR, HIPAA, NIST 800-53, PCI-DSS, TSC).
- **Rule ID:** 554 (file-added), 553 (file-deleted)
- **Severity:** Level 5
- **Relevant event:** Syscheck file-added / file-deleted / registry-checksum-changed events; 40 hits for the day across file and registry activity.
- **Screenshot evidence:** Yes: ossec.conf configuration, Wazuh FIM event list, alert detail with compliance mapping, who-data alert detail, and content-diff alert detail are all referenced in the source report.

## False Positives / Noise

**Observed:**
- Registry monitoring under `HKEY_LOCAL_MACHINE` generated a steady stream of checksum-changed events, since Windows touches those keys on its own during normal operation. This is noise, not a security event, and ignore rules needed tuning so real test events didn't get lost in the background.

**Potential (not directly claimed as observed beyond the above):**
- Broader FIM monitoring on system-wide directories in a real environment could similarly surface routine OS/application activity as alerts if not tuned.

## Limitations

- **Lab-only validation**: tested in a controlled home lab, not a production environment.
- **Registry noise**: monitoring `HKEY_LOCAL_MACHINE` keys produces routine Windows-generated checksum-changed events that require tuning to avoid drowning out real signal.
- **No custom rule / relies on defaults**: detection here comes from Wazuh's built-in syscheck rules (554, 553) plus configuration, not a custom-authored rule with additional correlation logic.
- **Naming collisions during testing**: similar file names (`malware`, `malware-exe`) across different test phases made it easy to correlate the wrong dashboard event to the wrong test.

## What I Learned

- Configuring Wazuh's syscheck (FIM) module on a Windows agent
- Understanding the difference between scheduled, realtime, and who-data monitoring modes
- Reading Wazuh's automatic compliance mapping (GDPR, HIPAA, NIST 800-53, PCI-DSS, TSC)
- Using who-data mode for user/process attribution
- Reading syscheck content diffs and hash-based change detection
- Recognizing Wazuh's automatic MITRE ATT&CK tagging
- Tuning ignore rules to reduce registry monitoring noise
- Troubleshooting Wazuh agent config changes (requires service restart to take effect)

## Evidence

- `ossec.conf`: monitored directories, restrict rules, and registry keys on the Windows agent
- Wazuh FIM event list: add/delete/modify events for files and registry keys, with rule ID and level
- Alert detail for the `malware-exe` file-added event, with compliance references auto-attached by Wazuh
- Who-data alert: responsible user, process, and the MITRE technique Wazuh auto-tagged
- Second modification alert: MITRE T1565.001 re-confirmed, plus the exact before/after content diff and hashes
