# RDP Brute-Force Detection PoC

## Overview

This PoC tests whether Wazuh detects an RDP brute-force attack against a Windows 10 endpoint. Hydra was run from a Kali attacker VM against the RDP service, first against Wazuh's default ruleset, then against two custom correlation rules written for this case.

RDP brute-forcing is security-relevant because RDP is a common initial-access and lateral-movement vector; repeated failed logon attempts from a single source are a strong signal of an automated credential-guessing attack rather than a legitimate user mistyping a password.

What I was trying to detect: not just individual failed logons (which Wazuh's default rules already catch), but an explicit brute-force *verdict*: correlating a burst of failures into a single, clearly labeled alert.

## Lab Environment

| Machine | Role | Operating System | Purpose |
|---|---|---|---|
| DESKTOP-TDOGRJA | Target / Victim | Windows 10 x64 | RDP endpoint under attack; Wazuh agent installed |
| Wazuh Manager | SIEM | Ubuntu Server (Docker, single-node) | Log correlation, custom rule matching, alerting |
| Kali Attacker | Attacker | Kali Linux 2026.2 | Hydra-based RDP brute-force tool |

## Objective

The objective was to run Hydra against a Windows RDP endpoint, confirm what Wazuh's default rules caught on their own, and write custom correlation rules that turn the raw failed-logon events into an explicit, clearly labeled brute-force alert.

## Attack / Test Scenario

1. **Initial setup**: Windows 10 endpoint with the Wazuh agent installed, targeted directly on its RDP service from a Kali attacker VM.
2. **Attack execution**: Hydra targeted the RDP service directly:
   ```
   hydra -l Victim -P pass.txt rdp://192.168.142.130
   ```
   The first several runs failed outright: Hydra's RDP module reported connection errors instead of logon failures (see Troubleshooting). Once resolved, the attack generated a string of Windows Event ID 4625 failures on the target.
3. **What happened on the victim**: Repeated failed RDP logon attempts against the account `Victim`, using a fixed password list.
4. **Telemetry generated**: Windows Security Event ID 4625 ("An account failed to log on") for each failed attempt, decoded by Wazuh's `windows_eventchannel` handling.
5. **How Wazuh received the telemetry**: Via the Wazuh agent on the Windows endpoint, forwarding the Windows Security event log to the manager.

### Baseline Detection (Default Rules)

Before any custom rule was added, Wazuh's default ruleset already caught the failed logons individually: rule 60122 ("Logon Failure, Unknown user or bad password," level 5) fired on every attempt, and rule 60204 ("Multiple Windows Logon Failures," level 10) fired once the failure count crossed Wazuh's built-in threshold. Over a 24-hour window this produced 515 hits, accurate, but noisy, and not labeled as a brute-force verdict on its own.

## Detection Logic

Two rules were added to `local_rules.xml` on the Wazuh manager to turn the raw failures into an explicit brute-force verdict:

- **Rule 100100** escalates on top of the existing 60204 multiple-failure rule, at level 15, tagged `rdp` in its group list.
- **Rule 100101** narrows the same behavior further, correlating failures by *source IP* instead of by account, using frequency/timeframe correlation: 8 failed logons within a 240-second window from the same `win.eventdata.ipAddress`, matched against the `authentication_failed` group.

| Field | Rule 100101 |
|---|---|
| ID | 100101 |
| Level | 15 |
| Description | Custom: Windows Brute Force (8 failed logons from same IP) |
| Groups | attack, bruteforce, authentication, local |
| Frequency | 8 |
| Timeframe | 240 seconds |
| if_matched_group | authentication_failed |
| same_field | win.eventdata.ipAddress |
| MITRE Technique | Brute Force (T1110) |
| MITRE Tactic | Credential Access |

## Wazuh Rule

```xml
<group name="local">
<rule id="100100" level="15">
<if_sid>60204</if_sid>
<description>Custom: RDP Brute Force Detected</description>
</rule>
</group>
```

> Complete rule XML for rule 100101 was not included in the source report. The following fields **are** documented and listed above: ID 100101, level 15, description "Custom: Windows Brute Force (8 failed logons from same IP)," groups `attack, bruteforce, authentication, local`, frequency 8, timeframe 240 seconds, `if_matched_group` of `authentication_failed`, and `same_field` of `win.eventdata.ipAddress`.

## MITRE ATT&CK

| Tactic | Technique | ID | Notes |
|---|---|---|---|
| Credential Access | Brute Force | T1110 | Wazuh's rule metadata tags rules 100100 and 100101 under this technique |
| Credential Access | Password Guessing | T1110.001 | Hydra ran a fixed password list against a single known username (`Victim`) over RDP |

## Validation

- **Attack performed:** Re-ran the Hydra attack with both custom rules active.
- **Expected result:** An explicit, clearly labeled brute-force verdict alert, in addition to the existing default-rule logon-failure noise.
- **Actual Wazuh alert:** Rule 100100 (level 15, "Custom: RDP Brute Force Detected") fired alongside default rules 60122 and 60115; rule 100101 (level 15, "8 failed logons from same IP") fired after the frequency threshold was reached.
- **Rule ID:** 100100, 100101
- **Severity:** Level 15 (both)
- **Relevant event:** Windows Event ID 4625 (An account failed to log on), Provider `Microsoft-Windows-Security-Auditing`, Computer `DESKTOP-TDOGRJA`, Severity `AUDIT_FAILURE`.
- **Dashboard filter used:** `rule.id:(100100 OR 100101)` under Threat Hunting.
- **Screenshot evidence:** Yes: Hydra attack output, default-rule hits before the custom rule, rule 100100 confirmed in `local_rules.xml`, rule 100101 detail in the Rule Manager, both alerts firing during validation, and the Event ID 4625 detail are all referenced in the source report.

## Troubleshooting

### Problem
The first attack runs didn't produce any Windows-side failures at all. Hydra returned connection errors instead of logon attempts:
```
freerdp: The connection failed to establish
[ERROR] all children were disabled due too many connection errors
0 of 1 target completed, 0 valid password found
```

### Investigation
Hydra's own warning explained why: the RDP module is marked experimental and doesn't tolerate many parallel connections: the default of 4 tasks was enough to get attempts refused before they reached the login prompt.

### Fix
Dropped the task count (`-t 1` to `-t 4`) and added a wait between attempts (`-W 1` to `-W 3`), as Hydra's warning suggested. A leftover `hydra.restore` file from the failed runs also had to be cleared before Hydra would start a fresh session instead of trying to resume the broken one.

### Result
Hydra completed all 12 login attempts and Windows logged a 4625 event for each.

## False Positives / Noise

No false positive was reported as directly observed against the custom rules (100100, 100101) in this exercise.

**Potential (documented in context, not directly claimed as observed against the custom rules):** the default rule 60122 fires on every individual logon failure, which by itself is not a brute-force signal: a single mistyped password would also trigger it. That's precisely the noise the custom correlation rules (100100, 100101) were built to filter into an explicit brute-force verdict rather than raw per-attempt noise.

## Limitations

- **Fixed username target**: the attack (and by extension this validation) used a single known username (`Victim`); the detection logic wasn't tested against username-spraying variations (many usernames, few passwords each).
- **IP-based correlation is bypassable**: rule 100101 correlates by source IP; a distributed brute-force attack from many source IPs would not trigger this specific rule's frequency threshold.
- **Complete rule XML for 100101 not available**: only the documented fields (above) are available from the source report, not the full XML implementation.
- **Lab-only validation**: tested against a single Windows 10 endpoint in a controlled environment.

## What I Learned

- Running and tuning Hydra against RDP (including working around its experimental RDP module's concurrency limits)
- Reading Windows Event ID 4625 and Wazuh's default authentication-failure rules
- Writing frequency/timeframe correlation rules (`if_matched_group`, `same_field`, `frequency`, `timeframe`)
- Escalating on top of existing built-in rules (`if_sid`) rather than rebuilding detection logic from scratch
- Distinguishing "detected the individual event" from "correctly labeled the pattern" in detection engineering
- MITRE ATT&CK mapping for brute-force and password-guessing techniques

## Evidence

- Hydra RDP brute-force attempts against 192.168.142.130, including the early connection failures before the retry
- Default rule hits (60122, 60204) before the custom rule was added
- Rule 100100 added on the Wazuh manager container and confirmed in `local_rules.xml`
- Rule 100101 detail in Wazuh's Rule Manager, showing the frequency/timeframe correlation and MITRE ATT&CK tags
- Rule 100100 firing alongside default rules 60122 and 60115
- Rule 100101 firing after the frequency threshold was reached
- Event ID 4625 detail, decoded by Wazuh's `windows_eventchannel` handling
