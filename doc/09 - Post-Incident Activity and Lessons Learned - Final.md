# Post-Incident Activity and Lessons Learned

## Overview

With the attacker contained, malicious persistence removed, and the Nexus Financial environment returned to a trusted state, I moved into the final phase of the incident response lifecycle: **Post-Incident Activity**.

At this point, the immediate technical threat had been addressed, but the incident was not finished from an Incident Response perspective.

The purpose of this phase was to step back from the active investigation and answer a different set of questions:

- What exactly happened?
- Why was the attack successful?
- Which security controls failed?
- Which controls helped detect or limit the incident?
- Could the attack have been detected earlier?
- What should change to prevent the same type of compromise from happening again?
- What new detections can be created from the attacker's behaviour?

I treated this phase as the point where the technical findings from the investigation were converted into improvements for the organisation.

The incident therefore became more than a security event that had been resolved. It became a source of intelligence that could improve Nexus Financial's future detection, response, and prevention capabilities.

---

## Objectives

During this phase, I focused on:

- Reviewing the complete Nexus Financial incident.
- Reconstructing the attack timeline.
- Identifying the root causes and security-control gaps.
- Reviewing what worked and what failed during the response.
- Documenting Indicators of Compromise discovered during the investigation.
- Mapping attacker behaviour to MITRE ATT&CK techniques.
- Identifying detection gaps.
- Converting attacker TTPs into future detection opportunities.
- Understanding the difference between technical and executive incident reporting.
- Evaluating improvements to people, process, and technology.
- Feeding the lessons learned back into the Preparation phase.

---

## Why Post-Incident Activity Matters

One of the most important lessons I took from this phase is that successfully removing an attacker does not automatically mean the incident response process is complete.

An organisation may successfully:

- Disable compromised accounts.
- Revoke malicious sessions.
- Remove persistence.
- Reset credentials.
- Restore access.
- Strengthen authentication controls.

However, if the organisation does not analyse why the incident happened, the same weaknesses may remain available to another attacker.

Post-Incident Activity is therefore where the long-term value of Incident Response is created.

The attacker revealed information about:

- Weak security controls.
- Missing detections.
- User behaviour.
- Logging visibility.
- Response procedures.
- Identity protections.
- Attack techniques.
- Business exposure.

All of this information can be used to improve the environment.

---

## Closing the Incident Response Cycle

I treated Incident Response as a continuous improvement process rather than a sequence that ends after recovery.

The lessons identified during Post-Incident Activity should feed directly back into **Preparation**.

The cycle therefore becomes:

```text
Preparation
    ↓
Detection and Analysis
    ↓
Containment, Eradication and Recovery
    ↓
Post-Incident Activity
    ↓
Improved Preparation
```

For Nexus Financial, this was particularly important because the investigation showed that some of the weaknesses involved in the compromise had already been identified before the incident.

The incident demonstrated why security findings should not simply be documented and forgotten. Identified weaknesses must be assigned, prioritised, remediated, and validated.

---

## Incident Review

The incident began with an anomalous sign-in alert involving the Microsoft 365 account:

```text
l.chen@nexusfinancial.thm
```

The initial alert was raised on:

```text
2026-03-30 16:41:30
```

The normal corporate IP used by Nexus Financial employees was:

```text
197.32.45.112
```

The suspicious authentication originated from outside the expected corporate environment.

Laura Chen confirmed that she had not initiated the sign-in, causing the alert to be treated as a true positive and escalated for Incident Response investigation.

The escalation was recorded as:

| Field | Value |
|---|---|
| Ticket ID | `NXF-SOC-2026-0312` |
| Raised By | Marcus Webb – Security Analyst L1 |
| Assigned To | IR Analyst L2 |
| Severity | High |
| Affected Account | `l.chen@nexusfinancial.thm` |

The wider investigation later established that the incident was part of a targeted phishing campaign against Nexus Financial.

The investigation identified:

- Credential harvesting through phishing.
- Compromise of two Microsoft 365 accounts.
- Successful attacker authentication using stolen credentials.
- Sign-ins from infrastructure outside the normal corporate environment.
- Malicious inbox rules designed to suppress security-related messages.
- Internal phishing sent from a compromised account.
- Access to sensitive SharePoint resources.
- File downloads from SharePoint.
- External sharing activity.
- Missing or insufficient identity protections.

The incident was eventually contained, attacker access was removed, and the affected environment was restored with stronger controls.

## Initial Suspicious Authentication Evidence

I validated the initial suspicious authentication in the Entra ID sign-in logs.

```spl
index=ir sourcetype="azure:aad:signin"
userPrincipalName="l.chen@nexusfinancial.thm"
ipAddress!="197.32.45.112"
| table _time userPrincipalName ipAddress location.city location.countryOrRegion appDisplayName status.errorCode
| sort 0 _time
```

The results showed Laura Chen's account authenticating from the confirmed attacker IP `223.123.4.50` in Amsterdam, Netherlands.

The first suspicious attempt appeared at `2026-03-30 16:41:28` with `status.errorCode=50140`, followed by a successful sign-in at `2026-03-30 16:41:30` with `status.errorCode=0`.

The field `location.countryOrRegion` exposed the unusual country value `NL`, making it useful for future detections involving unexpected authentication locations.

<img width="1892" height="857" alt="Ekran görüntüsü 2026-09-18 215852" src="https://github.com/user-attachments/assets/00c64056-a61e-46c0-8dba-79c268e2110a" />


## Internal Phishing Evidence

I then validated the internal phishing activity sent from Laura Chen's compromised mailbox.

```spl
index=ir sourcetype="o365:reporting:messagetrace"
SenderAddress="l.chen@nexusfinancial.thm"
FromIP="223.123.4.50"
| table Received SenderAddress RecipientAddress Subject Status FromIP
| sort 0 Received
```

The message trace returned three delivered phishing emails with the subject:

```text
HR Policy Update — Immediate Action Required
```

The messages were delivered to:

- `allan.senna@nexusfinancial.thm`
- `m.harris@nexusfinancial.thm`
- `k.patel@nexusfinancial.thm`

This confirmed that **3 employees were placed at risk by the internal phishing campaign**.

<img width="1867" height="382" alt="Ekran görüntüsü 2026-09-18 220431" src="https://github.com/user-attachments/assets/d1765369-8588-4dbd-bb99-e4af05fdd271" />

## Sensitive SharePoint Access

I reviewed SharePoint download activity associated with both compromised identities and the confirmed attacker IP.

```spl
index=ir sourcetype="o365:management:activity"
Operation="FileDownloaded"
(UserId="l.chen@nexusfinancial.thm" OR UserId="k.patel@nexusfinancial.thm")
ClientIP="223.123.4.50*"
| table _time UserId SourceFileName ObjectId ClientIP
| sort 0 _time
```

The search returned five file downloads. The most sensitive file identified was:

```text
Full_Employee_PII_Data.xlsx
```

It was downloaded through `k.patel@nexusfinancial.thm` at `2026-03-30 17:03:38` from the attacker IP `223.123.4.50`.

The filename indicates exposure of personally identifiable information belonging to Nexus Financial employees and therefore increased the potential business and regulatory impact of the incident.

<img width="1871" height="457" alt="Ekran görüntüsü 2026-09-18 220032" src="https://github.com/user-attachments/assets/b12ec9e9-aed4-4fb0-a947-7e2b45fbf6df" />

---

## Lessons Learned Review

After an incident is resolved, I would conduct a structured lessons-learned review with the people involved in the response.

The purpose is not simply to describe what happened.

The review should identify what can be changed so the organisation responds more effectively to the next incident.

The main questions I would ask are:

- What was the root cause of the incident?
- How did the attacker gain initial access?
- What security weakness allowed the compromise to succeed?
- When did the malicious activity begin?
- When was the incident detected?
- Which event triggered the investigation?
- Could the attack have been detected earlier?
- What security controls worked correctly?
- Which controls failed or were missing?
- Were there any visibility gaps?
- Were there any response delays?
- Did the investigation have access to the required logs?
- Were containment and eradication actions effective?
- What should be changed in people, process, or technology?

The answers to these questions become actionable improvements rather than simply historical observations.

---

## Why Lessons Learned Are Often Skipped

Post-incident reviews are easy to delay.

After a major incident:

- Analysts may be tired.
- Stakeholders may want to return to normal operations.
- The SOC may already have new alerts waiting.
- Technical teams may consider the problem solved once the attacker is removed.

However, skipping the review creates a serious risk.

If the underlying problems remain unchanged, the organisation may face the same incident again.

The same phishing technique may work.

The same account protection weakness may remain.

The same attacker behaviour may still be invisible to the SIEM.

The same response delays may occur.

For this reason, I consider the lessons-learned process part of the incident itself rather than an optional administrative task.

---

## Technical and Executive Incident Reporting

The investigation produces information for two different audiences.

I would therefore separate the final incident documentation into:

1. **Technical Summary**
2. **Executive Summary**

These documents describe the same incident but serve different purposes.

---

### Executive Summary

The executive summary is intended for people such as:

- Senior management.
- Executives.
- Legal teams.
- Business stakeholders.
- Board members.

The objective is to explain the business impact of the incident without overwhelming the reader with technical details.

I would include:

#### What Happened

A clear description of the type of attack and which business systems or accounts were affected.

#### Business Impact

This should explain whether:

- Sensitive information was accessed.
- Business operations were disrupted.
- Employee or customer data may have been exposed.
- Regulatory or legal considerations exist.

#### Discovery and Resolution

A high-level explanation of:

- How the incident was detected.
- How the investigation progressed.
- How attacker access was removed.
- How normal operations were restored.

#### Prevention and Remediation

A plain-language explanation of the improvements being introduced after the incident.

I would avoid including unnecessary technical information such as:

- IP addresses.
- SPL queries.
- MITRE ATT&CK technique IDs.
- Raw log entries.
- Internal detection logic.

These details belong in the technical report.

---

### Technical Summary

The technical summary is intended for:

- SOC analysts.
- Incident responders.
- Detection engineers.
- Security engineers.
- System administrators.
- Other technical teams.

The goal is to preserve enough detail that another analyst could understand exactly what happened and use the investigation to improve future detection and response.

The technical summary should include:

#### Full Attack Timeline

Every important event should be documented in chronological order with timestamps.

This should cover activity from the earliest malicious action through detection, investigation, containment, eradication, and recovery.

#### Indicators of Compromise

All confirmed indicators should be documented, including where relevant:

- Attacker IP addresses.
- Email addresses.
- Domains.
- Compromised accounts.
- Mailbox rules.
- File names.
- SharePoint activity.
- External sharing destinations.

#### MITRE ATT&CK Mapping

MITRE ATT&CK techniques should not be listed as IDs alone.

Each technique should include the specific evidence that connected the attacker behaviour to the technique.

For example, documenting:

```text
T1564.008 – Email Hiding Rules
```

is not enough on its own.

A useful technical report should also record:

- Which account the rule was created on.
- The rule name.
- The keywords being filtered.
- The configured action.
- The source IP.
- The timestamp.
- The supporting audit log.

This level of detail allows the finding to be converted into a detection rule later.

#### Log Evidence

The technical summary should preserve:

- Log source.
- Sourcetype.
- Search query.
- Relevant fields.
- Supporting event.
- Timestamp.
- Analyst interpretation.

#### Root Cause

The report should document which security weaknesses allowed the attack to succeed.

#### Detection Gaps

Attacker actions that were recorded but did not generate alerts are particularly important.

These events represent opportunities to improve SIEM detection coverage.

---

## Evidence Sources

The post-incident review used the same Microsoft 365 evidence sources collected during the earlier investigation.

All logs were available in:

```spl
index=ir
```

The main data sources were:

| Log Source | Sourcetype | Investigation Purpose |
|---|---|---|
| Entra ID Sign-in Logs | `azure:aad:signin` | Authentication activity, source IPs, locations, accounts |
| Message Trace | `o365:reporting:messagetrace` | Phishing and internal email activity |
| Unified Audit Logs | `o365:management:activity` | Inbox rules, SharePoint access, sharing activity and Microsoft 365 actions |

The practical investigation will use these sources to reconstruct the complete incident timeline and confirm the final technical findings.

---

## Attack Timeline Reconstruction

One of my main tasks during the post-incident review was to reconstruct the confirmed attacker activity in chronological order.

The evidence collected in this room supports the following timeline:

| Time | Event | Evidence |
|---|---|---|
| `2026-03-30 16:41:28` | Suspicious authentication attempt against Laura Chen | Entra ID sign-in log from `223.123.4.50` |
| `2026-03-30 16:41:30` | Successful attacker sign-in to Laura Chen's account | Entra ID sign-in log, `status.errorCode=0` |
| `2026-03-30 16:55:24` | First confirmed SharePoint download through Laura Chen | `Board_Meeting_Notes_July.docx` |
| `2026-03-30 16:55:33` | Additional SharePoint download | `Employee_Salary_Data.xlsx` |
| `2026-03-30 16:55:37` | Additional SharePoint download | `Q3_Financial_Report.xlsx` |
| `2026-03-30 16:57:09` | Internal phishing sent to three employees | Message Trace |
| `2026-03-30 16:58:48` | Malicious inbox rule created on Laura Chen's mailbox | `New-InboxRule` – `Junk Filter Update` |
| `2026-03-30 17:02:40` | Malicious inbox rule created on K. Patel's mailbox | `New-InboxRule` – `Security Updates` |
| `2026-03-30 17:03:38` | PII file downloaded through K. Patel | `Full_Employee_PII_Data.xlsx` |
| `2026-03-30 17:03:45` | Additional payroll data downloaded | `Payroll_Q3_2024.xlsx` |

This sequence shows how quickly the attacker moved from identity compromise to data access, internal phishing, persistence, and additional sensitive-data access.

The earlier phishing delivery and the final containment timestamp are not established by the evidence collected in this room, so I did not calculate a complete incident dwell time from unsupported timestamps.

---

## Dwell Time

Dwell time is the period between an attacker's initial malicious activity and the point at which the organisation detects or contains the compromise.

For this case, I can confidently reconstruct the confirmed post-compromise activity shown above. However, a full dwell-time calculation would require the timestamp of the earliest confirmed malicious phishing activity and the final containment point.

I therefore did not assign a dwell-time value that the available evidence could not support.

---

## From TTPs to Detection Rules

Every attacker action recorded during this investigation can be treated as a potential detection opportunity.

The attacker's Tactics, Techniques, and Procedures provide more value than a simple IOC list because they describe **behaviour**.

An IP address may change.

A phishing domain may disappear.

An email address may only be used once.

But an attacker may continue using the same behaviour.

For example:

- Signing in using stolen credentials.
- Creating inbox rules that suppress security messages.
- Downloading unusual volumes of sensitive files.
- Sending internal phishing from a compromised identity.
- Creating external sharing links.

These behaviours can be converted into detection logic.

This is how the incident feeds directly back into Preparation.

---

## Detection Opportunities Identified

The Nexus Financial incident showed several examples where individual user actions might appear legitimate but become suspicious when correlated with surrounding activity.

Potential detection opportunities include:

#### Suspicious Inbox Rule After Anomalous Sign-In

Creating an inbox rule is normal user behaviour.

However, an inbox rule created shortly after a sign-in from a new country or unknown IP should be considered more suspicious.

Example correlation:

```text
Anomalous sign-in
        +
New inbox rule
        +
Security-related keywords
        +
DeleteMessage = True
```

---

#### High-Volume SharePoint Downloads

Employees regularly download files from SharePoint.

A useful detection therefore should not alert on every download.

Instead, I would look for unusual patterns such as:

```text
Single account
        +
Multiple sensitive files
        +
Short time window
        +
Unusual source IP
```

---

#### Successful Sign-In Without MFA

A successful sign-in becomes more significant when several risk factors exist together.

For example:

```text
Previously unseen IP
        +
New geographic location
        +
Successful authentication
        +
No MFA
```

---

#### External Sharing After Suspicious Authentication

Another useful detection opportunity is:

```text
Anomalous sign-in
        ↓
Sensitive SharePoint access
        ↓
External sharing event
```

This correlation is more useful than detecting each activity independently.

## Inbox Rule Detection Evidence

I validated the mailbox-persistence behaviour through the Unified Audit Logs.

```spl
index=ir sourcetype="o365:management:activity"
Operation="New-InboxRule"
| table _time UserId Operation Name SubjectContainsWords DeleteMessage ClientIP
| sort 0 _time
```

The search returned two suspicious inbox-rule creation events:

| Time | Account | Rule | Keywords | DeleteMessage |
|---|---|---|---|---|
| `2026-03-30 16:58:48` | `l.chen@nexusfinancial.thm` | `Junk Filter Update` | `security;alert;suspicious;password;verify` | `True` |
| `2026-03-30 17:02:40` | `k.patel@nexusfinancial.thm` | `Security Updates` | `security;alert;password` | `True` |

Both events were associated with the confirmed attacker IP `223.123.4.50`.

For future detection engineering, the relevant Microsoft 365 audit operation is:

```text
New-InboxRule
```

I would not alert on every inbox-rule creation. I would correlate `New-InboxRule` with conditions such as an anomalous sign-in, a previously unseen IP, security-related filtering keywords, or `DeleteMessage=True`.

<img width="1890" height="332" alt="Ekran görüntüsü 2026-09-18 220141" src="https://github.com/user-attachments/assets/bea49f04-3aac-4047-b3fc-ed4ba5a21534" />

---

## Avoiding False Positives

A major lesson from this phase is that detection engineering must balance visibility with alert quality.

Many attacker behaviours look similar to legitimate user actions.

Examples include:

- Creating mailbox rules.
- Downloading files.
- Sharing documents.
- Signing in from new locations.

Alerting on every occurrence would create large numbers of false positives.

This could lead to **alert fatigue**, where analysts spend so much time reviewing benign activity that real attacks become harder to identify.

I would therefore prefer correlation and context over single-event detection whenever possible.

A stronger detection rule considers:

- Who performed the action.
- Where the activity originated.
- What happened immediately before it.
- What happened immediately after it.
- Whether the behaviour is normal for the user.
- Whether the resource involved is sensitive.
- Whether multiple suspicious indicators appear together.

This creates higher-value alerts and reduces unnecessary SOC workload.

---

## Detection Engineering as Continuous Improvement

No organisation begins with perfect detection coverage.

The Nexus Financial incident demonstrated that some attacker behaviour was visible in logs even when no alert was generated.

That means the organisation had **visibility**, but not necessarily **detection**.

After the incident, those behaviours can be converted into detection logic.

The process becomes:

```text
Incident
   ↓
Investigation
   ↓
Attacker behaviour identified
   ↓
Detection gap discovered
   ↓
New detection rule created
   ↓
Rule tuned
   ↓
Future attacker detected earlier
```

As more incidents are investigated, the organisation's detection capability gradually improves.

---

## Microsoft 365 Post-Incident Investigation Tools

Because this incident involved Microsoft 365, I also reviewed tools that can support additional post-incident validation.

These tools were not part of the practical investigation, but they are relevant to Microsoft 365 Incident Response.

| Tool | Purpose |
|---|---|
| Hawk | Collects Microsoft 365 forensic information including mailbox, administrative and sign-in activity |
| Sparrow | Helps identify indicators of compromise associated with Microsoft 365 and Azure environments |
| Microsoft Secure Score | Provides visibility into the organisation's Microsoft 365 security posture and remaining configuration gaps |

These tools could provide additional validation before formally closing a real-world Microsoft 365 incident.

---

### People, Process and Technology Improvements

I grouped post-incident improvements into three areas.

### People

Potential improvements include:

- Additional phishing-awareness training.
- Training employees to identify unusual authentication requests.
- Improving internal reporting procedures.
- Providing analysts with more Microsoft 365 investigation experience.
- Conducting regular phishing simulations.

### Process

Potential process improvements include:

- Updating incident response playbooks.
- Defining clearer escalation timelines.
- Improving lessons-learned documentation.
- Tracking remediation actions until completion.
- Ensuring pentest findings receive owners and deadlines.
- Reviewing unresolved security findings.
- Maintaining a structured IOC tracker.
- Requiring post-incident reviews for significant incidents.

### Technology

Potential technical improvements include:

- Enforcing MFA.
- Implementing stronger Conditional Access policies.
- Improving email authentication controls.
- Expanding identity monitoring.
- Improving SharePoint access monitoring.
- Creating correlation-based SIEM detections.
- Monitoring suspicious inbox-rule creation.
- Detecting anomalous file-download patterns.
- Monitoring external sharing of sensitive data.
- Improving sign-in anomaly detection.

---

## What Worked

Several parts of the security environment contributed to the investigation.

The SOC had access to multiple useful log sources, including:

- Entra ID sign-in logs.
- Microsoft 365 Unified Audit Logs.
- Message Trace data.

These logs allowed the investigation to reconstruct:

- Authentication activity.
- Mailbox changes.
- Internal phishing.
- SharePoint access.
- File downloads.
- Other Microsoft 365 actions.

The initial anomalous sign-in alert also provided the starting point for the investigation and allowed the incident to be escalated.

---

## What Needs Improvement

The incident also demonstrated several weaknesses.

The investigation showed the importance of strengthening:

- Identity protection.
- MFA enforcement.
- Detection coverage.
- Email security.
- SharePoint monitoring.
- Correlation between identity and Microsoft 365 activity.
- Follow-up on previously identified security findings.

The biggest lesson is that identifying a weakness is not enough.

A finding only improves security when it is actually remediated and validated.

---

## Post-Incident Outputs

At the end of the review, I would expect the incident to produce two main documents.

### Technical Output

The technical report should preserve:

- Full attack timeline.
- IOC list.
- MITRE ATT&CK mapping.
- Splunk evidence.
- Detection gaps.
- Root causes.
- Containment actions.
- Eradication actions.
- Recovery actions.
- Recommended detections.

### Executive Output

The executive report should explain:

- What happened.
- Which business areas were affected.
- What the business impact was.
- How the incident was resolved.
- What improvements are being implemented.

The same incident is therefore communicated differently depending on the audience.

---

## Final Lessons Learned

This phase changed how I view Incident Response.

The objective is not only to detect an attacker and remove them from the environment.

A complete response should also make the organisation harder to compromise the next time.

The Nexus Financial investigation showed how one incident can reveal weaknesses across identity security, phishing protection, cloud monitoring, detection engineering, and response processes.

By reconstructing the attacker's actions, documenting the root causes, identifying missed detection opportunities, and converting the attacker's behaviour into new defensive controls, the organisation can turn the incident into an improvement opportunity.

The most important principle I take from this phase is:

> **An incident should leave the organisation better prepared than it was before the attack.**

The Post-Incident Activity phase therefore closes the current incident while simultaneously beginning preparation for the next one.
