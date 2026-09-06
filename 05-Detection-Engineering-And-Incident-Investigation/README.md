# 5. Detection Engineering and Incident Investigation

With Windows Security events successfully flowing into Microsoft Sentinel, I used the collected telemetry to build and test a custom detection for repeated failed authentication attempts.

The objective was to simulate a common SOC detection workflow:

**Generate suspicious activity → Identify the telemetry → Query the events → Build a detection rule → Generate an incident → Investigate the alert**

For this lab, repeated Windows logon failures were used to simulate activity that could indicate password guessing or attempted unauthorized access.

---

## Generating Failed Authentication Activity

To create controlled security events, I generated several failed Windows authentication attempts against a test account named `FakeSOCUser`.

```powershell
runas /user:FakeSOCUser cmd
```

An intentionally incorrect password was entered repeatedly, causing Windows to reject the authentication attempts.

![Failed Windows Authentication Attempts](02-Azure-Lab-Environment/windows-failed-logon-generation.png)

The failed attempts returned:

```text
RUNAS ERROR: Unable to run - cmd
1326: The user name or password is incorrect.
```

This provided a predictable source of failed authentication telemetry that could be used to test detection logic.

---

## Identifying Failed Logon Events in Microsoft Sentinel

The generated activity was then queried through Microsoft Sentinel using Kusto Query Language (KQL).

Windows recorded the failed authentication attempts as:

**Security Event ID 4625 — An account failed to log on**

I queried the `SecurityEvent` table for Event ID `4625` associated with the test Windows system.

```kusto
SecurityEvent
| where TimeGenerated > ago(30m)
| where Computer contains "Alan-VM-Test"
| where EventID == 4625
| project TimeGenerated, Computer, EventID, Account, Activity
| sort by TimeGenerated desc
```

![Event ID 4625 Query Results](02-Azure-Lab-Environment/sentinel-4625-query-results.png)

The results confirmed that the failed authentication attempts generated on the Windows VM were successfully collected by the Log Analytics workspace and available for analysis in Microsoft Sentinel.

The events contained the expected test account:

```text
Alan-VM-Test\FakeSOCUser
```

and the corresponding activity:

```text
4625 - An account failed to log on.
```

At this point, the telemetry path had been verified:

```text
Windows VM
    ↓
Windows Security Event Log
    ↓
Azure Monitor Agent
    ↓
Log Analytics Workspace
    ↓
Microsoft Sentinel
    ↓
SecurityEvent Table
```

---

## Developing the Detection Logic

Rather than alerting on every individual failed authentication attempt, I created detection logic designed to identify multiple failures involving the same account and computer within a short period of time.

The KQL query used for the analytics rule was:

```kusto
SecurityEvent
| where EventID == 4625
| summarize
    FailedLogons = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by Account, Computer
| where FailedLogons >= 5
```

This query:

- Filters Windows Security telemetry for Event ID `4625`
- Groups the events by account and computer
- Counts the number of failed logons
- Records the first and last authentication attempts
- Returns a result when the number of failed logons reaches or exceeds five

![Sentinel Detection Query Test](02-Azure-Lab-Environment/sentinel-detection-query-test.png)

During testing, the query successfully identified the simulated activity and returned five failed logons associated with the test account and Windows VM.

```text
Account:      Alan-VM-Test\FakeSOCUser
Computer:     Alan-VM-Test
FailedLogons: 5
```

This confirmed that the detection logic worked before it was deployed as a scheduled analytics rule.

---

## Creating the Microsoft Sentinel Analytics Rule

The tested KQL query was then configured as a scheduled Microsoft Sentinel analytics rule.

The rule was configured with the following parameters:

| Setting | Configuration |
|---|---|
| Rule Name | Multiple Failed Logon Attempts - Alan Lab |
| Severity | Medium |
| Data Source | SecurityEvent |
| Windows Event ID | 4625 |
| Detection Threshold | 5 or more failed logons |
| Query Frequency | Every 5 minutes |
| Lookup Period | Previous 5 minutes |
| MITRE ATT&CK Tactic | Credential Access |
| Status | Enabled |

![Microsoft Sentinel Analytics Rule](02-Azure-Lab-Environment/sentinel-analytics-rule-review.png)

The detection was designed to identify repeated authentication failures while avoiding the creation of a separate alert for every individual failed login.

The rule also mapped the relevant **Account** and **Host** information as entities. This allows Microsoft Sentinel to associate the user account and affected system with the resulting security incident and provides additional context during investigation.

---

## Triggering the Detection

After the analytics rule was enabled, additional failed authentication attempts were generated against the test account.

Microsoft Sentinel evaluated the incoming `SecurityEvent` records against the scheduled analytics rule.

Once the threshold was satisfied, Sentinel generated an incident:

**Multiple Failed Logon Attempts - Alan Lab**

![Microsoft Sentinel Incident Generated](02-Azure-Lab-Environment/sentinel-incident-generated.png)

The resulting incident was classified as:

```text
Severity:      Medium
Status:        New
Tactic:        Credential Access
Alert Product: Microsoft Sentinel
```

This demonstrated that the custom detection successfully converted raw Windows Security telemetry into an actionable security incident.

---

## Investigating the Incident

I opened the generated incident to review the associated alert, timeline, and entities.

![Microsoft Sentinel Incident Investigation](02-Azure-Lab-Environment/sentinel-incident-overview.png)

Microsoft Sentinel associated two important entities with the incident:

```text
Account
Alan-VM-Test\FakeSOCUser

Host
Alan-VM-Test
```

The incident timeline also displayed the alert generated by the analytics rule.

Entity mapping provides useful investigation context because an analyst can immediately identify both the account involved in the authentication failures and the endpoint on which the activity occurred.

---

## Reviewing the Underlying Security Events

I then returned to the underlying `SecurityEvent` telemetry to validate the activity responsible for the detection.

A more targeted KQL query was used to isolate the test account:

```kusto
SecurityEvent
| where Computer == "Alan-VM-Test"
| where EventID == 4625
| where Account contains "FakeSOCUser"
| project
    TimeGenerated,
    Computer,
    Account,
    LogonType,
    IpAddress,
    WorkstationName,
    FailureReason,
    SubStatus,
    Activity
| sort by TimeGenerated desc
```

![Failed Logon Investigation](02-Azure-Lab-Environment/sentinel-failed-logon-investigation.png)

The query returned multiple Event ID `4625` records associated with the same test account and Windows host.

The investigation confirmed that the incident was generated by the intentionally created authentication failures and that the analytics rule behaved as expected.

---

## Detection Workflow

The completed detection pipeline can be summarized as:

```text
Failed Authentication Attempts
            ↓
Windows Event ID 4625
            ↓
Azure Monitor Agent
            ↓
Log Analytics / SecurityEvent
            ↓
KQL Detection Logic
            ↓
Microsoft Sentinel Analytics Rule
            ↓
Threshold: ≥5 Failed Logons
            ↓
Security Alert
            ↓
Microsoft Sentinel Incident
            ↓
Account + Host Investigation
```

This portion of the lab demonstrated how endpoint telemetry can be transformed into a usable SOC detection rather than simply collected and stored.

---

## MITRE ATT&CK Mapping

The analytics rule was mapped to the **Credential Access** tactic in Microsoft Sentinel.

The repeated failed authentication activity represented behavior that could be associated with attempts to obtain access to an account through repeated credential guesses.

In this controlled environment, the authentication failures were intentionally generated for detection testing rather than representing an actual attack.

---

## Analyst Findings

The investigation established the following sequence of events:

1. Multiple failed authentication attempts occurred against `FakeSOCUser`.
2. Windows recorded the failures as Security Event ID `4625`.
3. Azure Monitor forwarded the Windows Security telemetry to the Log Analytics workspace.
4. Microsoft Sentinel made the events available through the `SecurityEvent` table.
5. The custom KQL detection identified five or more failed logons associated with the same account and computer.
6. The scheduled analytics rule generated a Medium-severity Microsoft Sentinel incident.
7. Sentinel associated the affected account and host with the incident.
8. Investigation of the underlying events confirmed that the alert corresponded to the intentionally generated test activity.

Because this activity was generated as part of the lab, the incident was determined to be a **true positive for the detection logic but benign test activity in context**.

---

## What I Learned

This portion of the project demonstrated the difference between **collecting security logs** and **turning telemetry into actionable detections**.

I gained hands-on experience with:

- Windows Security Event ID `4625`
- Microsoft Sentinel `SecurityEvent` telemetry
- Kusto Query Language (KQL)
- Filtering and aggregating authentication events
- Threshold-based detection logic
- Scheduled Microsoft Sentinel analytics rules
- Alert and incident generation
- Account and host entity mapping
- MITRE ATT&CK classification
- Incident investigation and validation
- Distinguishing a detection true positive from malicious activity

Most importantly, this portion of the lab demonstrated the complete detection lifecycle:

**Telemetry → Query → Detection → Alert → Incident → Investigation**

---

[← Back to Main Project](../README.md)
