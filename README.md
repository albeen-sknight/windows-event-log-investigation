# Windows Event Log Investigation: Auditing Settings Modification Analysis

## Project Overview

This repository documents a hands-on Windows Event Log investigation completed in a controlled Hack The Box Academy lab environment. The goal of the lab was to investigate Windows Security logs, correlate related events using a shared Logon ID, and identify the executable responsible for modifying auditing settings on a Windows system.

This project is written as a portfolio-style SOC analyst investigation. It focuses on the process: identifying the starting event, extracting a useful pivot field, building XML filters, reviewing related events, and documenting the final finding.

> **Note:** This was completed in a training lab environment. Live target IPs, credentials, and other sensitive lab-access details are intentionally excluded from this repository.

---

## Lab Objective

Investigate a Windows Security event with **Event ID 4624**, identify the related logon session, and determine which executable modified auditing settings for a specific Windows file.

The investigation required answering two main questions:

1. Which executable was responsible for modifying auditing settings?
2. At what time did the executable modify auditing settings for the target DLL file?

---

## Tools and Environment

- Hack The Box Academy lab environment
- Pwnbox
- Remote Desktop Protocol / RDP
- Windows Event Viewer
- Windows Security Logs
- Manual XML filtering
- Windows Event ID correlation

---

## Key Concepts Practiced

- Windows Event Log investigation
- Security log filtering
- Event ID analysis
- Logon ID correlation
- XML query construction
- Process attribution
- Timeline analysis
- Basic SOC triage workflow
- SIEM investigation fundamentals

---

## Key Windows Event IDs

| Event ID | Description | Relevance to Investigation |
|---:|---|---|
| 4624 | Successful logon | Starting point of the investigation |
| 4672 | Special privileges assigned to a new logon | Helpful for identifying privileged activity |
| 4907 | Auditing settings on an object were changed | Main event used to identify auditing modification |
| 1102 | Audit log was cleared | Important indicator of possible log tampering |
| 4698 | Scheduled task was created | Useful for detecting persistence activity |
| 7045 | Service was installed | Useful for detecting suspicious service creation |

---

## Investigation Methodology

The investigation followed a SOC-style workflow:

```text
Start with known event → Extract useful field → Pivot into related logs → Filter suspicious events → Review details → Document findings
```

The known starting point was a successful logon event:

```text
Event ID: 4624
Timestamp: 8/3/2022 10:23:25
Log source: Windows Security Log
```

After opening the event details, the relevant Logon ID was identified:

```text
Logon ID: 0x3E7
```

This Logon ID was then used as a pivot value to find related events from the same session.

---

## XML Query: Correlating Event ID 4907 with Logon ID

The following XML query was used in Windows Event Viewer to filter for auditing modification events associated with the identified Logon ID:

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[
        System[(EventID=4907)]
        and
        EventData[Data[@Name='SubjectLogonId']='0x3E7']
      ]
    </Select>
  </Query>
</QueryList>
```

The matching events were reviewed in the **Details** tab. The relevant field was:

```text
ProcessName
```

The executable responsible for the auditing settings modification was identified as:

```text
TiWorker.exe
```

---

## XML Query: Filtering for the Target DLL

The investigation then focused on whether the same activity affected the following file:

```text
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\WPF\wpfgfx_v0400.dll
```

A more specific XML query was used to filter for the target object path:

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[
        System[(EventID=4907)]
        and
        EventData[Data[@Name='SubjectLogonId']='0x3E7']
        and
        EventData[Data[@Name='ObjectName']='C:\Windows\Microsoft.NET\Framework64\v4.0.30319\WPF\wpfgfx_v0400.dll']
      ]
    </Select>
  </Query>
</QueryList>
```

The matching event was then reviewed to identify the event timestamp in `HH:MM:SS` format.

---

## Findings

| Field | Value |
|---|---|
| Initial Event ID | 4624 |
| Initial Event Timestamp | 8/3/2022 10:23:25 |
| Correlation Field | Logon ID / SubjectLogonId |
| Logon ID | 0x3E7 |
| Related Event ID | 4907 |
| Executable Identified | TiWorker.exe |
| Target Object | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\WPF\wpfgfx_v0400.dll |
| Activity Type | Auditing settings modification |

---

## Screenshots

Add screenshots to the `assets/` folder using the following names:

```text
screenshot-01.png
screenshot-02.png
screenshot-03.png
...
screenshot-19.png
```

### 1. Lab target spawned

![Screenshot 01 - Lab target spawned](assets/screenshot-01.png)

---

### 2. Pwnbox environment ready

![Screenshot 02 - Pwnbox environment](assets/screenshot-02.png)

---

### 3. RDP connection to the Windows lab machine

![Screenshot 03 - RDP connection](assets/screenshot-03.png)

---

### 4. Windows desktop after successful login

![Screenshot 04 - Windows desktop](assets/screenshot-04.png)

---

### 5. Opening Windows Event Viewer

![Screenshot 05 - Event Viewer opened](assets/screenshot-05.png)

---

### 6. Windows Logs expanded

![Screenshot 06 - Windows Logs expanded](assets/screenshot-06.png)

---

### 7. Security log selected

![Screenshot 07 - Security log selected](assets/screenshot-07.png)

---

### 8. Filtering for Event ID 4624

![Screenshot 08 - Filtering Event ID 4624](assets/screenshot-08.png)

---

### 9. Successful logon event located

![Screenshot 09 - Event ID 4624 found](assets/screenshot-09.png)

---

### 10. Event details showing Logon ID 0x3E7

![Screenshot 10 - Logon ID identified](assets/screenshot-10.png)

---

### 11. Enabling manual XML query editing

![Screenshot 11 - XML query enabled](assets/screenshot-11.png)

---

### 12. XML query using SubjectLogonId

![Screenshot 12 - SubjectLogonId XML query](assets/screenshot-12.png)

---

### 13. Filtering for Event ID 4907

![Screenshot 13 - Event ID 4907 filtered](assets/screenshot-13.png)

---

### 14. Related auditing modification events found

![Screenshot 14 - Auditing modification events](assets/screenshot-14.png)

---

### 15. ProcessName field showing TiWorker.exe

![Screenshot 15 - TiWorker executable identified](assets/screenshot-15.png)

---

### 16. ObjectName field showing the target file path

![Screenshot 16 - ObjectName target file](assets/screenshot-16.png)

---

### 17. XML query for the specific DLL path

![Screenshot 17 - DLL-specific XML query](assets/screenshot-17.png)

---

### 18. Matching event timestamp identified

![Screenshot 18 - Matching event time](assets/screenshot-18.png)

---

### 19. Lab answer submitted successfully

![Screenshot 19 - Lab completed](assets/screenshot-19.png)

---

## Why This Matters for SOC Analysis

This lab represents a core SOC analyst skill: using logs to reconstruct system activity.

A SIEM alert usually does not give the full story by itself. Analysts need to pivot across logs, correlate events, and answer questions such as:

- What happened?
- When did it happen?
- Which user or account was involved?
- Which process performed the action?
- Which file, object, or system component was affected?
- Is this expected administrative activity or potentially suspicious behavior?

This investigation shows the same logic used in SIEM tools, but at the raw Windows Event Log level.

---

## SIEM Translation

In a SIEM such as Splunk, Microsoft Sentinel, Elastic, QRadar, or Chronicle, this same investigation could be translated into a query that searches for Windows Security events and correlates on fields such as:

```text
EventCode
SubjectLogonId
ProcessName
ObjectName
User
Host
_time
```

Example detection logic:

```text
Search for Event ID 4907
Filter or group by SubjectLogonId
Review ProcessName and ObjectName
Correlate with Event ID 4624
Build a timeline of related activity
Determine whether the action is expected or suspicious
```

This project helped reinforce the foundation behind SIEM investigations: understanding the raw logs before depending on dashboards or automated alerts.

---

## Lessons Learned

This lab reinforced that a single Windows event rarely tells the entire story. The real value comes from correlating events using shared fields such as Logon ID, Process Name, Object Name, timestamps, and user context.

It also showed that legitimate Windows executables can appear in security-relevant events. Analysts should not assume an executable is safe or malicious based only on its name. Context, timing, parent activity, file paths, and surrounding events matter.

---

## Portfolio Summary

This project demonstrates practical blue-team investigation skills relevant to SOC Analyst, SIEM Analyst, and Cybersecurity Analyst roles.

### Skills Demonstrated

- Windows Event Viewer usage
- Windows Security Log analysis
- Event ID correlation
- XML event filtering
- Logon ID pivoting
- Process attribution
- Timeline analysis
- Documentation of technical findings
- SOC-style investigative thinking

---

## Repository Structure

```text
windows-event-log-investigation/
├── README.md
├── .gitignore
└── assets/
    ├── README.md
    ├── screenshot-01.png
    ├── screenshot-02.png
    ├── screenshot-03.png
    └── ...
```

---

## Disclaimer

This repository is for educational and portfolio purposes only. The investigation was performed in an authorized lab environment. No real-world systems were targeted, and sensitive lab access details have been removed.

---

## Tags

`Windows Event Logs` `SOC Analyst` `SIEM` `Blue Team` `Event Viewer` `Incident Investigation` `Threat Hunting` `Cybersecurity Lab` `Hack The Box` `Log Analysis`
