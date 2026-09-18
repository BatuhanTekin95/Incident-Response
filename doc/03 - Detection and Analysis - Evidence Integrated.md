# Detection and Analysis

## Overview

In this phase of the Nexus Financial incident, I worked through the **Detection and Analysis** stage of the NIST SP 800-61r2 Incident Response lifecycle.

The investigation started from a single SOC escalation involving an anomalous Microsoft 365 sign-in.

My responsibility was not only to confirm whether the alert represented a genuine security incident, but also to determine:

- How the attacker gained access.
- Which account was initially compromised.
- Whether additional accounts were affected.
- What actions the attacker performed after gaining access.
- Which data or resources may have been exposed.
- How far the incident had spread.

I treated Detection and Analysis as two closely connected activities.

**Detection** answered:

> Did a real security incident occur, and how did the attacker get in?

**Analysis** answered:

> What happened after the compromise, and what is the full extent of the incident?

The quality of this phase is critical because every containment, eradication, and recovery decision depends on understanding the incident correctly.

---

## Learning Objectives

During this phase, I focused on:

- Understanding Detection and Analysis as a NIST Incident Response phase.
- Understanding how detection and analysis work together.
- Validating an L1 SOC escalation as an L2 analyst.
- Distinguishing true-positive activity from false positives.
- Identifying the initial attack vector.
- Tracing attacker activity across Microsoft 365 logs.
- Identifying compromised accounts.
- Determining the scope of the phishing campaign.
- Reviewing post-compromise attacker activity.
- Understanding the Detection and Analysis feedback loop.
- Reviewing common Incident Response trigger sources.
- Understanding communication requirements during an active incident.
- Using an Asset Inventory during incident analysis.
- Maintaining an IOC Tracker throughout the investigation.
- Using Splunk to investigate Entra ID, Message Trace, and Microsoft 365 Unified Audit Logs.

---

## Incident Response Module Context

This investigation is part of a four-stage Nexus Financial Incident Response scenario:

| Phase | Purpose |
|---|---|
| Preparation | Review security posture and identify weaknesses before the incident |
| **Detection and Analysis** | **Confirm the incident and investigate attacker activity** |
| Response and Recovery | Contain the incident, remove attacker access, and restore the environment |
| Post-Incident Activity | Reconstruct the attack, identify lessons learned, and improve future detection |

The security gaps identified during Preparation became directly relevant during this investigation.

These included:

- Lack of MFA on standard user accounts.
- Weak email authentication controls.
- Previous phishing-related weaknesses that were not fully remediated.
- Detection gaps for important attack scenarios.

The Detection and Analysis phase showed how those weaknesses could be exploited in a real incident.

---

## Understanding Detection and Analysis

According to the NIST Incident Response model, Detection and Analysis is the phase where an organisation determines whether a security incident has occurred and develops a complete understanding of the attack.

In a large organisation, this work may be handled by a dedicated Incident Response team.

In smaller environments, SOC analysts may perform both SOC and IR responsibilities.

Nexus Financial follows this model.

The workflow is divided between analyst levels.

---

## SOC L1 and L2 Responsibilities

### SOC L1 Analyst

The L1 analyst performs the initial alert triage.

Typical responsibilities include:

- Reviewing the initial alert.
- Checking the affected user or device.
- Reviewing basic supporting evidence.
- Checking suspicious IP addresses or domains.
- Contacting the user when required.
- Determining whether the alert appears to be a true positive or false positive.
- Escalating confirmed suspicious activity.

The L1 analyst does not normally perform the complete Incident Response investigation.

The objective is to provide enough validated information for the next analyst to continue the investigation.

### SOC L2 Analyst

The L2 analyst performs deeper investigation.

Responsibilities may include:

- Validating the L1 analyst's findings.
- Investigating the root cause.
- Identifying the initial access method.
- Tracing the attack chain.
- Searching for additional compromised accounts.
- Reviewing attacker activity across multiple log sources.
- Identifying IOCs.
- Determining the scope of the compromise.
- Building the complete incident narrative.

During this investigation, I worked from the perspective of the assigned L2 analyst.

I did not automatically assume the L1 conclusion was correct.

My first responsibility was to independently validate the escalation using the available evidence.

---

## Detection

Detection is the process of confirming that suspicious activity represents a genuine security incident.

An alert alone does not prove that an incident occurred.

The alert provides a starting point for investigation.

Potential detection sources include:

- SIEM alerts.
- EDR alerts.
- User reports.
- Threat intelligence.
- Third-party notifications.
- Automated security detections.

The analyst must then validate the activity using available logs and organisational context.

The first question is:

> Is this activity malicious, suspicious, or legitimate?

This is where the analyst determines whether the alert is a **True Positive** or **False Positive**.

---

## Analysis

Once the incident is confirmed, the investigation moves deeper into analysis.

The objective is no longer only to prove that the alert is real.

I need to understand the complete attack.

This includes answering questions such as:

- How did the attacker gain initial access?
- Which credentials were compromised?
- Which user accounts were affected?
- Which systems or cloud resources were accessed?
- What actions did the attacker perform?
- Was persistence created?
- Was internal phishing performed?
- Was sensitive data accessed?
- Was data downloaded or externally shared?
- Did the attacker compromise additional identities?

Scoping is therefore an important part of analysis.

However, analysis goes beyond scoping.

It also involves:

- Correlating multiple log sources.
- Following attacker behaviour across systems.
- Mapping related events.
- Identifying Indicators of Compromise.
- Reconstructing attacker activity.
- Determining the complete attack narrative.

Incomplete analysis creates a serious risk.

If even one compromised identity, persistence mechanism, or malicious action is missed, the attacker may retain access after containment.

---

## Detection and Analysis Feedback Loop

Detection and Analysis do not operate as two completely separate steps.

They continuously feed into each other.

For example:

```text
Initial Alert
    ↓
Suspicious IP Identified
    ↓
IP Searched Across Other Accounts
    ↓
Additional Compromised Account Discovered
    ↓
Account Activity Investigated
    ↓
New IOC Identified
    ↓
IOC Searched Across Other Logs
    ↓
Additional Attacker Activity Found
```

Each new finding can create another detection opportunity.

An IOC discovered during analysis may reveal another compromised account.

That account may reveal additional malicious behaviour.

The cycle continues until the investigation stops producing new evidence and the scope can be established with confidence.

---

## Common Incident Response Triggers

An Incident Response investigation must begin with some form of trigger.

Relying only on automated SIEM alerts creates blind spots because not every attack generates a predefined detection.

Common IR triggers include:

| Trigger | Example |
|---|---|
| SOC Alert Escalation | SIEM detects an anomalous sign-in and L1 escalates it |
| User Report | Employee reports suspicious email or account activity |
| Automated Detection | EDR detects malicious process execution |
| Third-Party Notification | External organisation reports a compromise |
| Threat Intelligence | External IOC matches organisational activity |

Different trigger sources can detect incidents at different times.

A SIEM detection may identify activity within minutes.

A user may report suspicious activity hours later.

A third party may identify a compromise days later.

For this reason, multiple detection channels reduce the time an attacker can remain undetected.

---

### Nexus Financial Trigger

The Nexus Financial investigation began through a **SOC alert escalation**.

A basic geo-location detection rule identified a successful authentication from outside the expected corporate environment.

This detection was particularly important because Nexus Financial employees were expected to authenticate from the London corporate network.

Without that detection rule, the attacker may have remained unnoticed for longer.

---

## Team Communication During Incident Response

Technical investigation is only one part of Incident Response.

Communication also directly affects response speed.

Common communication failures include:

- Delayed escalation.
- Outdated contact lists.
- Slow approval for log access.
- Delayed responses from third-party providers.
- Investigation updates being communicated verbally but never documented.
- Unclear ownership of containment actions.

These delays give the attacker additional time to operate.

A strong Incident Response communication process should define:

- Who must be contacted.
- Who owns the investigation.
- When escalation should occur.
- Which teams can perform containment actions.
- How evidence and decisions must be documented.
- Maximum acceptable response times.

---

### Ticketing and Investigation Documentation

A ticketing system provides an auditable record of the incident.

During an investigation, I would document:

- Alerts.
- Investigation steps.
- Queries performed.
- IOCs discovered.
- Analyst findings.
- Decisions.
- Escalations.
- Containment actions.
- Communication with other teams.

This record later becomes valuable during the Post-Incident Activity and Lessons Learned phase.

---

## Asset Inventory

The Asset Inventory provides context about the organisation's environment.

During analysis, it can help answer questions such as:

- Who owns this system?
- What is the purpose of this server?
- Which accounts normally use this workstation?
- Is the asset business-critical?
- Which systems could the compromised account access?

Without an accurate inventory, an Incident Response team may fail to investigate systems that exist but are not properly documented.

For Nexus Financial, this is especially important because the organisation's preparation review identified gaps in asset tracking.

---

## IOC Tracker

During the investigation, I would maintain a continuously updated IOC Tracker.

The IOC Tracker records each suspicious or confirmed malicious indicator discovered during the incident.

Typical IOC types include:

| IOC Type | Example |
|---|---|
| IP Address | Attacker authentication IP |
| Domain | Credential-harvesting domain |
| Email Address | Phishing sender |
| User Account | Compromised Microsoft 365 account |
| File Name | Suspicious or sensitive file involved in the incident |

The IOC Tracker is not a static document.

Each new investigation finding can add additional indicators.

Those indicators can then be searched across other security logs.

This creates another investigation pivot.

---

## Nexus Financial Incident

The investigation began with the following SIEM alert.

### Initial Alert

| Field | Value |
|---|---|
| Alert Name | `Anomalous Sign-in Detected` |
| Time | `2026-03-30 16:41:30` |
| Affected Account | `l.chen@nexusfinancial.thm` |
| Account Owner | Laura Chen – Finance Manager |
| Corporate IP | `197.32.45.112` |

The alert indicated a successful authentication from an IP address that had never previously been observed in the Nexus Financial environment.

All Nexus Financial employees were expected to authenticate from the London corporate network.

The authentication originated from outside the United Kingdom.

Laura Chen confirmed that she had not performed the sign-in.

The L1 analyst therefore classified the activity as a true positive and escalated it.

---

### Escalation Ticket

| Field | Value |
|---|---|
| Ticket ID | `NXF-SOC-2026-0312` |
| Raised By | Marcus Webb – Security Analyst L1 |
| Assigned To | IR Analyst L2 |
| Severity | High |
| Affected Account | `l.chen@nexusfinancial.thm` |

At this point, I treated the escalation as the starting point of the investigation rather than the final conclusion.

My job was to validate the finding and determine the complete incident scope.

---

## Available Log Sources

All Microsoft 365 evidence was available in Splunk under:

```spl
index=ir
```

The investigation used three primary log sources.

| Log Source | Sourcetype | Important Fields |
|---|---|---|
| Entra ID Sign-in Logs | `azure:aad:signin` | `userPrincipalName`, `ipAddress`, `location.city`, `location.countryOrRegion`, `appDisplayName`, `status.errorCode` |
| Message Trace | `o365:reporting:messagetrace` | `Received`, `SenderAddress`, `RecipientAddress`, `Subject`, `Status`, `FromIP` |
| Unified Audit Logs | `o365:management:activity` | `Operation`, `UserId`, `Workload`, `ClientIP`, `ObjectId`, `SourceFileName`, `Name`, `SubjectContainsWords`, `DeleteMessage` |

For all practical searches, I used:

```spl
index=ir
```

with the time range set to:

```text
All Time
```

---

## Practical Investigation – Detection

The first practical objective was to validate the suspicious authentication involving Laura Chen.

I started with the Entra ID sign-in logs and compared Laura's activity against the known Nexus Financial corporate IP address.

### Splunk Investigation

```spl
index=ir sourcetype="azure:aad:signin"
userPrincipalName="l.chen@nexusfinancial.thm"
ipAddress!="197.32.45.112"
| table _time userPrincipalName ipAddress location.city location.countryOrRegion appDisplayName status.errorCode
| sort 0 _time
```

<img width="1894" height="862" alt="Ekran görüntüsü 2026-09-18 224015" src="https://github.com/user-attachments/assets/3900ee34-8cac-4523-8dde-ec84cfdadd6c" />

### Analyst Interpretation

The search returned **18 authentication-related events** associated with Laura Chen from the external IP:

```text
223.123.4.50
```

The activity originated from:

```text
Amsterdam, NL
```

An event appeared at `2026-03-30 16:41:28` with `status.errorCode=50140`. The first successful suspicious sign-in appeared at:

```text
2026-03-30 16:41:30
```

with:

```text
status.errorCode=0
```

This timestamp matched the original SIEM alert and independently validated the L1 analyst's escalation.

The authentication activity did not match Nexus Financial's expected corporate sign-in pattern because the organisation's known corporate IP was `197.32.45.112`.

I therefore confirmed the anomalous sign-in as malicious activity associated with the incident.

---

## Tracing the Initial Access Vector

After validating the suspicious authentication, the next question was:

> How did the attacker obtain Laura Chen's credentials?

Because the compromise occurred before the anomalous sign-in, I pivoted from Entra ID authentication logs to Microsoft 365 Message Trace.

I searched for messages delivered to Laura Chen before the successful suspicious authentication.

### Splunk Investigation

```spl
index=ir sourcetype="o365:reporting:messagetrace"
RecipientAddress="l.chen@nexusfinancial.thm"
| table Received SenderAddress RecipientAddress Subject Status FromIP
| sort 0 Received
```

<img width="1900" height="406" alt="Ekran görüntüsü 2026-09-18 224256" src="https://github.com/user-attachments/assets/32ad6f65-8263-4758-86b5-d85099ada792" />

### Analyst Interpretation

The search returned four messages delivered to Laura Chen.

One message stood out because it arrived shortly before the suspicious sign-in and originated from an external sender:

```text
Sender: hr-support@nexus-verify.thm
Sender domain: nexus-verify.thm
Subject: HR Policy Update — Immediate Action Required
Received: 2026-03-30 16:20:01.693Z
Status: Delivered
```

The sender attempted to impersonate a legitimate HR communication while using the lookalike domain:

```text
nexus-verify.thm
```

The phishing email was delivered approximately 21 minutes before the first successful suspicious authentication.

This established **phishing** as the initial attack vector and provided the most likely explanation for how Laura Chen's credentials were stolen.

---

## Practical Investigation – Analysis

After confirming Laura Chen's compromise and identifying the initial phishing email, I expanded the investigation beyond the original account.

The objective was to determine whether the attacker had used the same infrastructure against other Nexus Financial identities and to identify post-compromise actions.

I investigated:

- Whether the attacker's IP appeared on other accounts.
- Whether additional accounts were compromised.
- Whether mailbox persistence was created.
- Whether the original phishing campaign targeted additional employees.

---

### Searching the Attacker IP Across All Accounts

The confirmed attacker IP became the next investigation pivot:

```text
223.123.4.50
```

I searched all Entra ID sign-in records for activity from that IP.

```spl
index=ir sourcetype="azure:aad:signin"
ipAddress="223.123.4.50"
| stats count by userPrincipalName
```

<img width="1881" height="302" alt="Ekran görüntüsü 2026-09-18 224431" src="https://github.com/user-attachments/assets/0ecc0017-dd60-4895-8655-bc03e9b208f6" />

### Analyst Interpretation

The search showed authentication activity from the attacker IP against **two Nexus Financial accounts**:

| Account | Event Count |
|---|---:|
| `k.patel@nexusfinancial.thm` | 39 |
| `l.chen@nexusfinancial.thm` | 18 |

This expanded the incident scope beyond Laura Chen.

The second compromised account was:

```text
k.patel@nexusfinancial.thm
```

The result also demonstrated the value of IOC pivoting: a single confirmed attacker IP revealed an additional compromised identity that was not part of the original escalation ticket.

---

## Post-Compromise Activity

After identifying multiple affected accounts, I reviewed Microsoft 365 Unified Audit Logs for suspicious mailbox activity.

One important attacker objective after compromising a mailbox is to hide security notifications and maintain access without drawing attention.

I searched for inbox-rule creation on Laura Chen's account.

```spl
index=ir sourcetype="o365:management:activity"
Operation="New-InboxRule"
UserId="l.chen@nexusfinancial.thm"
| table _time UserId Name SubjectContainsWords DeleteMessage ClientIP
```

<img width="1867" height="289" alt="Ekran görüntüsü 2026-09-18 224530" src="https://github.com/user-attachments/assets/8c5e1789-5d7e-4314-b42b-764c44947e0e" />

### Analyst Interpretation

The search identified a suspicious inbox rule created on Laura Chen's mailbox:

```text
Rule Name: Junk Filter Update
```

The rule was created at:

```text
2026-03-30 16:58:48
```

and contained the following subject keywords:

```text
security;alert;suspicious;password;verify
```

The rule was configured with:

```text
DeleteMessage=True
```

and originated from:

```text
223.123.4.50:13651
```

This behaviour is consistent with mailbox manipulation and defence evasion because security-related messages matching those keywords could be automatically deleted before the victim noticed them.

The relevant Microsoft 365 audit operation was:

```text
New-InboxRule
```

---

## Phishing Campaign Scope

Finally, I returned to Message Trace to determine whether the original phishing email had targeted additional Nexus Financial employees.

I searched for all messages sent from the confirmed phishing sender:

```spl
index=ir sourcetype="o365:reporting:messagetrace"
SenderAddress="hr-support@nexus-verify.thm"
| table Received SenderAddress RecipientAddress Subject Status FromIP
| sort 0 Received
```

<img width="1880" height="326" alt="Ekran görüntüsü 2026-09-18 224557" src="https://github.com/user-attachments/assets/681fc29e-b1d9-4cf2-a6cc-0ba7e989591f" />

### Analyst Interpretation

The search returned two delivered phishing messages.

The recipients were:

- `l.chen@nexusfinancial.thm`
- `k.patel@nexusfinancial.thm`

Both messages used the same subject:

```text
HR Policy Update — Immediate Action Required
```

This confirmed that the initial phishing campaign targeted **2 Nexus Financial employee accounts**.

The campaign scope also aligned with the sign-in evidence, which later showed attacker activity from `223.123.4.50` against both accounts.

---

## Confirmed Investigation Findings

At this stage, I had enough evidence to establish the following findings:

| Finding | Confirmed Value |
|---|---|
| Initial alert | `Anomalous Sign-in Detected` |
| First successful suspicious sign-in | `2026-03-30 16:41:30` |
| Attacker IP | `223.123.4.50` |
| Suspicious city | `Amsterdam` |
| Country | `NL` |
| Initial compromised account | `l.chen@nexusfinancial.thm` |
| Initial attack vector | Phishing |
| Phishing sender | `hr-support@nexus-verify.thm` |
| Phishing sender domain | `nexus-verify.thm` |
| Phishing subject | `HR Policy Update — Immediate Action Required` |
| Accounts targeted by initial phishing | 2 |
| Accounts showing attacker-IP sign-in activity | 2 |
| Second compromised account | `k.patel@nexusfinancial.thm` |
| Laura's malicious inbox rule | `Junk Filter Update` |
| Inbox-rule operation | `New-InboxRule` |
| Rule action | `DeleteMessage=True` |

### IOC Tracker Update

The investigation produced several confirmed indicators that should be carried forward into the Response and Recovery phase:

| IOC Type | Indicator | Context |
|---|---|---|
| IP Address | `223.123.4.50` | Attacker authentication and mailbox activity |
| Domain | `nexus-verify.thm` | Phishing sender domain |
| Email Address | `hr-support@nexus-verify.thm` | Initial phishing sender |
| User Account | `l.chen@nexusfinancial.thm` | Initial compromised account |
| User Account | `k.patel@nexusfinancial.thm` | Second compromised account |
| Mailbox Rule | `Junk Filter Update` | Security-message suppression on Laura's mailbox |

---

## Building the Incident Picture

The investigation started with only:

```text
One anomalous sign-in alert
```

From that single detection, the analysis process was designed to expand into:

```text
Anomalous Sign-In Alert
        ↓
Laura Chen Sign-In Validated
        ↓
Attacker IP Identified: 223.123.4.50
        ↓
Phishing Email Identified
        ↓
Sender Domain Identified: nexus-verify.thm
        ↓
Initial Access Vector Confirmed: Phishing
        ↓
Attacker IP Pivoted Across Entra ID
        ↓
Second Compromised Account Identified: k.patel@nexusfinancial.thm
        ↓
Malicious Inbox Rule Identified
        ↓
Initial Phishing Campaign Scope Confirmed: 2 Accounts
        ↓
Incident Scope Expanded and Confirmed
```

This demonstrates why detection and analysis operate as a feedback loop rather than isolated tasks.

---

## Detection and Analysis Lessons

This phase reinforced several important SOC and Incident Response principles for me.

### An alert is only the beginning

A SIEM alert does not provide the complete incident picture.

It gives the analyst a starting point.

The investigation must validate the alert and determine what happened around it.

### L1 and L2 responsibilities are different

L1 triage confirms whether activity appears legitimate or malicious and provides the initial escalation context.

L2 investigation goes deeper into root cause, attack chain, attacker activity, and incident scope.

### Every IOC can become a pivot

An IP address, account, domain, or email sender can reveal additional attacker activity when searched across other logs.

### Detection and analysis continuously feed each other

New evidence can create new detections.

Those detections can reveal more evidence.

The investigation continues until the scope becomes stable.

### Multiple log sources are essential

No single Microsoft 365 log source explained the complete incident on its own.

I needed to correlate:

- Entra ID authentication logs.
- Message Trace.
- Unified Audit Logs.

Together, they provide a much stronger incident picture.

### Communication affects containment time

Technical detection alone is not enough.

Slow escalation, incomplete documentation, or delayed access to logs gives the attacker additional time to operate.

---

## Transition to Response and Recovery

At the end of Detection and Analysis, the goal is to have enough confidence in the investigation to answer:

- How did the attacker gain access?
- Which accounts were compromised?
- Which systems or cloud resources were affected?
- Which attacker actions were performed?
- Which IOCs were identified?
- What data may have been accessed?
- What persistence mechanisms were created?
- What is the confirmed scope of the incident?

Once these questions are answered, the investigation can move from:

> **Understanding the incident**

to:

> **Containing and removing the attacker**

The next phase is **Response and Recovery**, where the confirmed scope from this investigation is used to make containment, eradication, and recovery decisions.

---

## Key Takeaways

- Detection confirms whether a real security incident occurred.
- Analysis determines the full scope and impact of the compromise.
- L1 performs initial triage and escalation.
- L2 validates the escalation and leads deeper investigation.
- Alerts must be independently validated.
- Scoping is a core part of analysis.
- Detection and analysis operate as a continuous feedback loop.
- IR investigations may begin from several different trigger sources.
- Multiple detection channels reduce attacker dwell time.
- Communication and documentation directly affect response speed.
- Asset inventories provide essential environmental context.
- IOC Trackers allow newly discovered indicators to be preserved and reused as investigation pivots.
- Splunk correlation across Entra ID, Message Trace, and Unified Audit Logs can reconstruct Microsoft 365 attacker activity.
- A single anomalous sign-in can become the starting point for uncovering a much larger compromise.




