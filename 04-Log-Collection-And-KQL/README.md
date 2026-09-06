# Log Collection and KQL

## Overview

After configuring the Windows 11 virtual machine, the next step was to collect Windows Security Event logs and make them available for analysis in Microsoft Sentinel.

Windows security events generated on the virtual machine were collected through Azure Monitor and sent to the Log Analytics workspace used by Microsoft Sentinel.

This allowed me to use Kusto Query Language (KQL) to search and analyze security activity from the endpoint.

---

## Windows Security Event Collection

The **Windows Security Events via AMA** data connector was used to collect Windows Security Event logs from the virtual machine.

The connector uses the Azure Monitor Agent (AMA) and a Data Collection Rule (DCR) to send Windows Security Events to the Log Analytics workspace.

The log collection path for this lab was:

**Windows 11 VM → Azure Monitor Agent → Data Collection Rule → Log Analytics Workspace → Microsoft Sentinel**

The Windows Security Events via AMA connector showed a connected status and confirmed that security event data was being received.

![Windows Security Events via AMA](windows-security-events-ama.png)

---

## Data Collection Rule

A Data Collection Rule was used to define the Windows event logs collected from the virtual machine and their destination.

The rule connected the Windows endpoint to Azure Monitor Logs, allowing the generated Windows Security Events to be stored in the Log Analytics workspace.

This provided the telemetry needed for KQL queries, detection rules, and incident investigation in Microsoft Sentinel.

![Data Collection Rule](data-collection-rule.png)

---

## Verifying Log Collection with KQL

After configuring log collection, I used Kusto Query Language (KQL) in Log Analytics to confirm that security events from the Windows 11 virtual machine were reaching the workspace.

The `SecurityEvent` table contains Windows Security Event data collected from the endpoint.

A basic query can be used to view events associated with the lab virtual machine:

```kusto
SecurityEvent
| where Computer == "Alan-VM-Test"
| sort by TimeGenerated desc
```

This allowed me to confirm that Windows security telemetry from the virtual machine was available for analysis.

---

## Investigating Failed Logon Events

To generate authentication activity for the lab, I intentionally attempted to authenticate using the test account:

`FakeSOCUser`

The failed authentication attempts generated:

**Windows Security Event ID 4625 — An account failed to log on**

I then used KQL to locate those events in Log Analytics.

```kusto
SecurityEvent
| where Computer == "Alan-VM-Test"
| where EventID == 4625
| where Account contains "FakeSOCUser"
| project TimeGenerated, Computer, Account, LogonType, IpAddress, WorkstationName, Activity
| sort by TimeGenerated desc
```

The query filtered the security telemetry by:

- Virtual machine
- Event ID
- Test account

It then displayed fields useful for investigating the authentication activity, including:

- `TimeGenerated`
- `Computer`
- `Account`
- `LogonType`
- `IpAddress`
- `WorkstationName`
- `Activity`

The query returned **13 failed logon events** associated with the `FakeSOCUser` test account.

![KQL Failed Logon Query](kql-failed-logons.png)

---

## Analyzing the Event Data

The query results confirmed that the failed authentication attempts generated on the Windows endpoint were successfully collected by Azure and available for investigation in Log Analytics.

The results showed:

- **Computer:** `Alan-VM-Test`
- **Account:** `Alan-VM-Test\FakeSOCUser`
- **Event ID:** `4625`
- **Logon Type:** `2`
- **IP Address:** `::1`
- **Workstation:** `Alan-VM-Test`
- **Activity:** `4625 - An account failed to log on`

This demonstrated the connection between activity occurring on the Windows endpoint and the security telemetry available to a SOC analyst in Microsoft Sentinel.

---

## KQL Investigation Workflow

This portion of the lab demonstrated a basic SOC investigation workflow:

**Generate security activity → Collect endpoint telemetry → Query the logs → Filter suspicious activity → Analyze the results**

Instead of reviewing individual Windows events manually, KQL allowed me to quickly search the collected telemetry and isolate the events associated with the simulated failed authentication activity.

The same process can be used by SOC analysts to investigate larger datasets and identify security events that require further analysis.

---

## Key Takeaways

This portion of the lab provided hands-on experience with:

- Collecting Windows Security Event logs
- Using Azure Monitor Agent (AMA)
- Working with Data Collection Rules
- Sending security telemetry to Log Analytics
- Querying the `SecurityEvent` table
- Writing and refining KQL queries
- Filtering logs by computer, Event ID, and account
- Investigating Windows Event ID 4625
- Identifying failed authentication activity
- Connecting endpoint activity to centralized SOC monitoring

The collected telemetry and KQL queries created the foundation for the next stage of the lab: **creating Microsoft Sentinel detections and investigating security incidents.**
