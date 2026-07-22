## Identification and Scoping

### Overview

After preparing the incident response capability, the next stage is to identify whether a security incident has occurred and determine the extent of the compromise.

In this scenario, SwiftSpend Financial received notifications indicating a potential security breach. The investigation required reviewing security alerts, interpreting available logs, gathering additional evidence, identifying suspicious artefacts, and determining which organisational assets may have been affected.

Identification and scoping are closely connected activities:

- **Identification** determines the nature of suspicious activity and whether it represents a genuine security incident.
- **Scoping** determines how far the compromise has spread and which systems, users, accounts, applications, or data may be affected.

The Asset Inventory and Spreadsheet of Doom support these activities by providing information about organisational systems and centralising Indicators of Compromise discovered during the investigation.

---

### Learning Objectives

This section covers:

- Identifying the nature of security alerts and event notifications.
- Understanding the relationship between people, processes, and technology.
- Gathering additional evidence from relevant security data sources.
- Understanding the importance of maintaining an accurate Asset Inventory.
- Using the Spreadsheet of Doom to document and enrich Indicators of Compromise.
- Determining the extent and potential impact of a security incident.
- Understanding the feedback loop between identification and scoping.
- Using artefacts as pivot points to expand an investigation.

---

## Identification

The Identification phase forms the foundation of the Incident Response process.

Its purpose is to recognise suspicious activity, determine whether the activity represents a genuine security incident, and ensure that the correct investigation and escalation procedures are initiated.

The speed at which an organisation identifies an incident directly affects its ability to respond. Early detection can:

- Reduce the time available to an attacker.
- Prevent the compromise from spreading.
- Limit operational and financial damage.
- Protect sensitive organisational data.
- Shorten the containment and recovery process.

Identification is not performed entirely by automated security tools. It depends on trained personnel, established procedures, and appropriate security technologies working together.

---

### People, Process, and Technology

Successful incident identification requires coordination between three primary elements:

#### People

People include employees, security analysts, administrators, managers, contractors, and other personnel who may detect or report suspicious activity.

Their responsibilities may include:

- Recognising unusual behaviour.
- Reporting suspicious emails or system activity.
- Reviewing security alerts.
- Escalating confirmed incidents.
- Following documented response procedures.
- Communicating findings to the appropriate teams.

Incident reporting is not limited to IT or Security personnel. A non-technical employee may detect the first visible sign of an incident before an automated security tool generates an alert.

#### Process

Processes define how suspicious activity should be reported, documented, investigated, escalated, and resolved.

A well-defined process should explain:

- Which activities should be reported.
- Which communication channels should be used.
- Who should receive the report.
- How alerts should be prioritised.
- What evidence should be collected.
- When an issue should be escalated.
- How investigation findings should be documented.

Without established procedures, important information may be lost, investigations may be delayed, and different teams may respond inconsistently.

#### Technology

Technology provides the visibility required to detect and investigate suspicious activity.

Security technologies may include:

- Endpoint Detection and Response platforms.
- Antivirus and endpoint protection products.
- Intrusion Detection and Prevention Systems.
- Security Information and Event Management platforms.
- Firewalls and proxy servers.
- Email security gateways.
- Authentication monitoring systems.
- Network traffic monitoring tools.
- Threat intelligence platforms.

Technology can generate alerts and collect evidence, but trained analysts are required to interpret the results and determine whether the activity is malicious.

---

### Security Alerts and Event Notifications

Security alerts, also referred to as event notifications, are signals that may indicate suspicious activity or a possible security incident.

An alert does not automatically confirm that an incident has occurred. It provides an initial lead that must be validated using additional evidence and organisational context.

When reviewing an alert, an analyst should determine:

- Which tool or individual generated the alert.
- When the activity occurred.
- Which user, account, or asset was involved.
- What type of activity was detected.
- How severe the alert is.
- Whether the activity is expected within the environment.
- Whether supporting evidence exists.
- Whether the alert is a true positive or false positive.
- Whether the activity requires escalation.

The type and severity of an alert influence how quickly the investigation should begin and which response procedures should be followed.

#### Initial Ticket Review

Two security-related tickets were reviewed during the initial triage. Ticket `2023012398704231` concerned outdated endpoint protection definitions on `LPTP-01` (`172.16.1.153`). Although this represented a security-control weakness requiring remediation, it did not initially contain direct evidence of the suspected phishing activity.

![Outdated endpoint protection ticket for LPTP-01](https://github.com/user-attachments/assets/411589e2-8c6e-44d1-8852-98d1a0c45840)

> A separate endpoint-protection ticket reviewed during initial triage.

Ticket `2023012398704232` reported a "Weird Error in Outlook" on `WKSTN-02` (`172.16.1.151`). The unusual Outlook behaviour became the starting point for the email-security investigation.

![Initial Outlook incident ticket for WKSTN-02](https://github.com/user-attachments/assets/439236a4-3ca1-4e37-b14a-35bdb64ae29e)

> The initial event notification that triggered the investigation into suspicious Outlook activity on WKSTN-02.


---

### Gathering Additional Evidence

The initial alert may not contain enough information to confirm an incident or determine its scope.

Additional evidence may therefore be collected from:

- Endpoint Detection and Response telemetry.
- Antivirus alerts.
- Windows Event Logs.
- Linux system logs.
- Firewall logs.
- Web proxy logs.
- DNS records.
- Authentication records.
- Email headers.
- Mail server logs.
- Message trace records.
- Browser history.
- Network traffic captures.
- File system artefacts.
- Process execution records.
- Registry changes.
- Suspicious files and attachments.
- User reports.
- Asset ownership records.

#### Evidence and Log Request

Following the review of Ticket `2023012398704232`, the Security Operations team requested Exchange Server logs and message trace records for `michael.ascot@swiftspend.finance` and `alex.swift@swiftspend.finance`.

Web proxy logs were also requested for `WKSTN-02` (`172.16.1.151`). These data sources were required to determine how the suspicious email was delivered, identify related recipients, and establish whether the affected workstation communicated with suspicious external infrastructure.

![Security Operations evidence and log request](https://github.com/user-attachments/assets/f4064391-81c5-4ca8-9c84-9f80599f65ee)

> Evidence collection request covering email activity for Michael Ascot and Alex Swift, together with web proxy logs for WKSTN-02.

#### Email Authentication Control Review

During the investigation, internal correspondence indicated that email authentication controls for `swiftspend.finance`, including SPF, DKIM, and DMARC, had not been fully implemented or maintained.

A domain-security check also reported that the organisation's domain was not adequately protected against spoofing and phishing abuse. This weakness increased the likelihood that attackers could impersonate internal email addresses and deliver fraudulent messages that appeared legitimate.

![Email authentication control review for swiftspend.finance](https://github.com/user-attachments/assets/05279063-205e-49e3-9973-89a62cab61d1)

> Review of the organisation's email authentication posture, highlighting insufficient protection against domain spoofing.

#### Delivery Failure and Message Header Review

An Outlook non-delivery report showed that a message addressed to `alex.swift@swiftspend.finance` could not be delivered because the recipient was not found. The subject line linked the failed message to the suspicious "Proposal from United Trust Company Limited" email thread.

![Outlook non-delivery report for the suspicious email](https://github.com/user-attachments/assets/d6770066-ce64-4ca6-a62b-b3ff093beb39)

> The non-delivery report preserved the recipient, timestamp, and subject needed to correlate the message with the incident ticket.

The original message headers were then reviewed. Although the visible sender and return path used `michael.ascot@swiftspend.finance`, the header recorded the external originating IP address `34.244.108.55`. The message references also contained the third-party domain `emkei.cz`. These inconsistencies supported the assessment that an internal address had been spoofed.

![Message headers showing sender spoofing indicators](https://github.com/user-attachments/assets/9d4005cd-5f80-467c-a85e-6893e1c10464)

> Header evidence showing the impersonated internal sender, external originating IP address, and third-party message reference.

#### User Report and Security Escalation

The investigation was also supported by a user report forwarded to the Security Operations team. The report described a suspected phishing attempt and requested an urgent investigation.

![User report of the suspected spoofed email](https://github.com/user-attachments/assets/9ce55164-8a0d-4b3d-b8dd-61dc22b4d42e)

> The forwarded user report provided business context and confirmed that the activity had been recognised as a potential security incident.

Security leadership escalated the report to IT Operations and the Security Operations team. The request focused on reviewing login activity, account usage, and recent logs so the team could determine whether unauthorised access had occurred and define the potential scope of the breach.

![Security escalation and request for log monitoring](https://github.com/user-attachments/assets/e14bfe9a-f042-42b5-89d9-ba4c3f10486b)

> The escalation message assigned investigation tasks and established the initial monitoring requirements.

The collected evidence helps analysts reconstruct the sequence of events and understand:

- How the incident began.
- Which user or asset was initially affected.
- Whether credentials were compromised.
- Whether malicious files were executed.
- Whether persistence was established.
- Whether lateral movement occurred.
- Whether data was accessed or exfiltrated.
- Whether the attacker remains active.

Evidence should be collected and documented carefully to preserve its integrity and maintain an accurate investigation timeline.

---

## Security Technologies Used During Identification

### Endpoint Detection and Response

Endpoint Detection and Response platforms monitor activity on workstations and servers.

They may provide visibility into:

- Process creation.
- Command-line execution.
- File creation and modification.
- Registry activity.
- Network connections.
- User behaviour.
- Malware detections.
- Persistence mechanisms.
- Suspicious parent-child process relationships.

Endpoint telemetry allows analysts to examine what occurred on a specific device and determine whether similar activity exists on other endpoints.

---

### Intrusion Detection and Prevention Systems

Intrusion Detection and Prevention Systems inspect network traffic for suspicious behaviour or known attack patterns.

They may identify:

- Network reconnaissance.
- Exploit attempts.
- Malicious payloads.
- Command-and-control communication.
- Suspicious protocols.
- Unusual traffic patterns.
- Connections to known malicious infrastructure.

These systems can generate alerts that become the starting point for a wider investigation.

---

### Security Information and Event Management

Security Information and Event Management platforms collect and centralise logs from multiple systems.

A SIEM can support incident identification by allowing analysts to:

- Search authentication activity.
- Review endpoint events.
- Correlate multiple log sources.
- Detect unusual behavioural patterns.
- Create investigation timelines.
- Search for Indicators of Compromise.
- Monitor activity across multiple assets.
- Create and improve detection rules.

Centralised visibility is particularly important when an incident affects several systems or user accounts.

---

### Communication and Reporting

Effective identification requires clear communication channels.

Employees should understand:

- What suspicious activity should be reported.
- How the report should be submitted.
- Which team should receive the report.
- What information should be included.
- How urgent events should be escalated.

A useful report may include:

- Date and time of the activity.
- Affected device or account.
- Description of the suspicious behaviour.
- Screenshots or error messages.
- Email sender information.
- File names or URLs.
- Actions already taken by the user.

Security teams must also communicate findings accurately. Poor communication can delay containment, cause important evidence to be overlooked, or result in the wrong teams responding to the incident.

---

### Security Awareness and Vigilance

A strong security culture encourages employees to remain vigilant and report suspicious activity without fear of blame.

Executive management should support this culture by providing:

- Security awareness training.
- Clear incident reporting procedures.
- Appropriate security technologies.
- Sufficient staffing and resources.
- Regular policy reviews.
- Support for continuous technical development.

Security awareness activities may cover:

- Phishing emails.
- Suspicious links and attachments.
- Unexpected password reset requests.
- Unusual multi-factor authentication prompts.
- Social engineering attempts.
- Lost or stolen devices.
- Unauthorised physical access.
- Accidental data exposure.
- Unexpected system behaviour.

Regular training improves the organisation's ability to recognise and report potential incidents.

---

## Transitioning from Identification to Scoping

After suspicious activity has been confirmed as an incident, the investigation moves into scoping.

Identification primarily answers:

> What happened?

Scoping begins answering:

- Which systems were affected?
- Which accounts were compromised?
- What data may be at risk?
- When did the incident begin?
- Is the activity still ongoing?
- Has the attacker moved to additional systems?
- How does the incident affect business operations?

The artefacts and evidence discovered during identification become the starting point for scoping.

For example, a suspicious domain discovered in an email can be searched across proxy and DNS logs. A malicious file hash can be searched across endpoint platforms. A compromised account can be reviewed across authentication records and other systems.

---

## Scoping the Incident

Scoping is the process of determining the full extent of a confirmed security incident.

The investigation should identify:

- The initially affected asset.
- Additional affected endpoints.
- Compromised user accounts.
- Malicious files or processes.
- Suspicious network connections.
- Persistence mechanisms.
- Lateral movement activity.
- The earliest known malicious event.
- The most recent malicious event.
- Business systems affected by the incident.
- Data that may have been accessed or exposed.
- The potential operational and financial impact.

Accurate scoping guides the next stages of Incident Response, including containment, eradication, and recovery.

If the scope is incomplete, affected systems may remain undetected and allow the attacker to maintain access to the environment.

---

## Asset Inventory

The Asset Inventory is a centralised record of the organisation's devices, systems, applications, and other technical resources.

It may contain:

- Asset type.
- Hostname.
- IP address.
- Operating system.
- Asset owner.
- Department.
- Physical or cloud location.
- Business purpose.
- Installed software.
- Security controls.
- Criticality level.
- Current operational status.

During an incident, the Asset Inventory allows analysts to identify:

- Who is responsible for an affected device.
- What purpose the asset serves.
- Whether the system is business-critical.
- Which operating system is installed.
- Where the device is located.
- Which other systems may be related to it.

The following assets were available during the SwiftSpend Financial investigation:

| Asset Type | Asset Name | IP Address | Operating System | Owner |
|---|---|---|---|---|
| Domain Controller | DC-01 | 172.16.1.10 | Windows Server 2019 | Derick Marshall |
| Mail Server | MAILSVR-01 | 172.16.1.15 | Windows Server 2019 | Stan Simon |
| Web Server | WEBSVR-01 | 172.16.1.110 | Ubuntu Server 20.04 | Damian Hall |
| Proxy Server | PROXY-01 | 172.16.1.119 | Windows Server 2019 | Stan Simon |
| Workstation | WKSTN-02 | 172.16.1.151 | Windows 10 Pro | Michael Ascot |
| Laptop | LPTP-01 | 172.16.1.153 | Windows 10 Pro | Derick Marshall |

An accurate Asset Inventory is essential because a hostname or IP address alone may not reveal the system's purpose, owner, or importance to the organisation.

---

## Spreadsheet of Doom

The Spreadsheet of Doom, commonly abbreviated as **SoD**, is a centralised record of Indicators of Compromise discovered during security investigations.

Each row represents a unique indicator or suspicious artefact.

The SoD may contain:

- IP addresses.
- Domain names.
- URLs.
- Email addresses.
- File names.
- File paths.
- File hashes.
- Hostnames.
- User accounts.
- Registry keys.
- Process names.
- Timestamps.
- Alert names.
- Related ticket numbers.
- Investigation notes.
- Threat classifications.
- Indicator sources.
- Current investigation status.

The spreadsheet acts as a single reference point for the incident response team and reduces the risk of important artefacts being lost or investigated repeatedly.

---

### Example Indicators

The following indicators were present in the investigation records:

| Indicator Type | Indicator | Threat Type | Source |
|---|---|---|---|
| IP Address | 188.40.75.132 | Malware Hosting | AlienVault OTX |
| Domain | b24b-158-62-19-6.ngrok-free.app | Phishing Domain | Ticket#2023012398704232 |
| Email Address | alex.swift@swiftspend.finance | Spoofed Email | Ticket#2023012398704232 |
| Email Address | michael.ascot@swiftspend.finance | Spoofed Email | Ticket#2023012398704232 |
| Domain | groupmarketingonline.icu | Phishing Domain | VirusTotal |
| File Hash (SHA1) | 75ec7d0d1b6b2b4c816cbc1b71cd0f8f06bd8c1b | Malware | ThreatCrowd |

The SoD can also be updated with newly discovered artefacts during the investigation.

---

### Indicator Enrichment

Indicator enrichment is the process of adding context to a suspicious artefact.

An IP address, domain, email address, or file hash may provide limited value without additional information.

Enrichment may determine:

- Whether the indicator has been reported as malicious.
- Which threat or malware family it is associated with.
- When it was first observed.
- When it was last observed.
- Which systems communicated with it.
- Whether it appeared in previous incidents.
- Which external source identified it.
- Whether it belongs to a known hosting provider.
- Whether the domain was recently registered.
- Whether the indicator is associated with a wider campaign.

Common enrichment sources include:

- VirusTotal.
- AlienVault OTX.
- Threat intelligence databases.
- WHOIS records.
- Passive DNS data.
- Internal SIEM records.
- Endpoint security platforms.
- Firewall and proxy logs.
- Email security records.
- Previous incident documentation.

Enrichment helps analysts understand the significance of an indicator and prioritise further investigation.

---

### Using Indicators to Expand the Scope

Indicators stored in the SoD can be searched across the organisation's security systems.

Examples include:

- Searching a suspicious domain in proxy and DNS logs.
- Searching an IP address in firewall and endpoint network records.
- Searching a spoofed email address in mail server logs.
- Searching a file hash across endpoint protection platforms.
- Searching a hostname in the Asset Inventory.
- Reviewing a user account across authentication logs.
- Searching a sender domain across all employee mailboxes.

If the same indicator appears on another system, the known scope of the incident may need to be expanded.

For example, if multiple workstations contacted the same phishing domain, the incident would no longer be limited to the system that generated the original ticket.

---

### Correlating the Asset Inventory and Spreadsheet of Doom

The Asset Inventory and Spreadsheet of Doom serve different but complementary purposes.

The Asset Inventory describes what exists in the organisation.

The Spreadsheet of Doom records what suspicious or malicious indicators have been discovered.

Together, they allow analysts to answer questions such as:

- Which asset communicated with a malicious IP address?
- Who owns the affected workstation?
- Which operating system is installed on the device?
- Is the system business-critical?
- Has the same malicious domain appeared on other systems?
- Are several users connected to the same suspicious email?
- Does the indicator relate to a previous incident?
- Which system should be isolated first?

This correlation supports faster and more accurate containment decisions.

---

## Identification and Scoping Feedback Loop

Identification and scoping do not follow a simple linear progression.

During an investigation, analysts continually discover new evidence, identify additional artefacts, and update their understanding of the incident.

Each finding may expand or reduce the known scope of the compromise.

The feedback loop consists of the following stages:

1. Event notification.
2. Documentation.
3. Evidence collection.
4. Artefact identification.
5. Pivot point discovery.
6. Updated documentation.
7. Repeated evidence collection and analysis.

The process continues until no further suspicious activity, artefacts, or affected assets are identified.

---

### Event Notification

The feedback loop begins when suspicious activity is detected or reported.

The notification may originate from:

- A security monitoring platform.
- An employee.
- A customer.
- A system administrator.
- A third-party organisation.
- An external threat intelligence source.
- An automated alerting system.

The notification triggers the Incident Response process and provides the first available information about the issue.

---

### Documentation

The reported issue should be documented in detail.

Initial documentation may include:

- Ticket number.
- Date and time of the report.
- Reporting individual.
- Description of the suspicious activity.
- Affected user or asset.
- Alert source.
- Alert severity.
- Initial Indicators of Compromise.
- Actions already taken.
- Assigned analyst.
- Current investigation status.

Documentation provides a central investigation record and supports communication between analysts, management, legal teams, and other stakeholders.

The record should be updated whenever new evidence or affected assets are discovered.

---

### Evidence Collection

Evidence is collected from relevant systems and data sources.

The evidence may reveal:

- The initial point of compromise.
- Attacker activity.
- Compromised credentials.
- Malicious files.
- Suspicious network connections.
- Persistence mechanisms.
- Lateral movement.
- Data access.
- Data exfiltration.
- Additional affected assets.

Each piece of evidence should be associated with an appropriate timestamp and source.

---

### Artefact Identification

Collected evidence is analysed to identify artefacts connected to the incident.

Potential artefacts include:

- IP addresses.
- Domain names.
- URLs.
- Email addresses.
- File names.
- File paths.
- File hashes.
- Registry keys.
- Scheduled tasks.
- Services.
- Process names.
- Command-line arguments.
- User accounts.
- Hostnames.
- Authentication timestamps.
- Message identifiers.

Relevant artefacts should be documented and added to the SoD when appropriate.

---

### Pivot Point Discovery

A pivot point is an artefact or piece of evidence that leads the investigation in a new direction.

Examples include:

- A malicious domain revealing additional network connections.
- A suspicious IP address appearing in logs from another endpoint.
- A file hash identifying the same malware on several systems.
- A compromised account authenticating from another device.
- A suspicious process revealing a persistence mechanism.
- An email sender being connected to additional phishing messages.
- A message identifier revealing the use of an external spoofing service.

Each pivot point creates a new opportunity to expand or refine the scope of the investigation.

---

### Example Investigation Loop

A practical feedback loop may operate as follows:

1. An employee reports an unusual Outlook error.
2. The issue is documented in an incident ticket.
3. Email, proxy, and message trace logs are requested.
4. A suspicious email address or phishing domain is identified.
5. The indicator is added to the Spreadsheet of Doom.
6. The indicator is searched across internal logs.
7. Another affected user or workstation is discovered.
8. The asset is confirmed using the Asset Inventory.
9. Additional evidence is collected from the newly identified system.
10. New artefacts are extracted.
11. The incident scope is updated.
12. The process repeats until no additional evidence is found.

An incident that initially appears to affect one user may therefore develop into a broader organisational compromise.

---

## Intelligence-Driven Investigation

The feedback loop becomes intelligence-driven when current investigation data is enriched using:

- Previous incident records.
- Historical Indicators of Compromise.
- Correlated SIEM logs.
- Endpoint telemetry.
- Firewall and proxy records.
- Authentication data.
- Email security logs.
- Threat intelligence platforms.
- Behavioural analytics.
- Automated detection systems.
- Machine learning models.

Combining current evidence with historical and contextual information can reveal that an apparently isolated incident is connected to a wider phishing campaign, recurring threat actor, or previous compromise.

---

### Correlation

Correlation connects related events from multiple data sources.

An analyst may correlate:

- An email delivery timestamp with a browser connection.
- A browser connection with a DNS query.
- A DNS query with a proxy record.
- A proxy record with an endpoint process.
- A process execution with a downloaded file.
- A file hash with threat intelligence results.
- A user login with a specific workstation.
- A suspicious message with other recipients.

Correlation helps reconstruct the attack timeline and identify relationships between otherwise isolated events.

---

### Advanced Analytics and Machine Learning

Advanced analytics can support incident responders by identifying patterns that may be difficult to detect manually.

These technologies may assist with:

- Detecting unusual authentication behaviour.
- Identifying abnormal network traffic.
- Grouping related alerts.
- Prioritising high-risk events.
- Detecting previously unseen attack patterns.
- Comparing current events with historical incidents.
- Reducing false-positive alerts.
- Identifying behavioural deviations.

Machine learning does not replace human analysis.

Analysts remain responsible for validating findings, understanding business context, and deciding how the incident should be handled.

---

## Privacy and Legal Considerations

Incident investigations may involve sensitive information, including:

- Employee information.
- Customer data.
- Authentication records.
- Email content.
- Network activity.
- Personal data.
- Confidential business information.

Evidence collection and analysis must follow organisational policies, legal requirements, and applicable data protection regulations.

The investigation team should document:

- Who collected the evidence.
- When the evidence was collected.
- Where the evidence was stored.
- Who accessed it.
- How it was analysed.
- Whether legal or regulatory notification is required.

Access to incident data should be limited to authorised personnel.

---

## Key Takeaways

- Identification is the foundation of the Incident Response process.
- Early detection can reduce the impact and duration of an incident.
- Identification depends on people, processes, and technology working together.
- Security alerts must be validated before an incident is confirmed.
- Additional logs and evidence are often required to understand suspicious activity.
- Scoping determines the full extent of a confirmed incident.
- The Asset Inventory provides context about affected systems and their owners.
- The Spreadsheet of Doom centralises Indicators of Compromise.
- Indicators should be enriched using internal and external data sources.
- Artefacts can be used as pivot points to discover additional affected assets.
- Identification and scoping operate as a continuous feedback loop.
- New evidence may expand or refine the known incident scope.
- Correlation connects related events across multiple security platforms.
- Automated analytics support but do not replace human investigation.
- Accurate documentation is essential throughout the entire process.
- Privacy, legal obligations, and evidence integrity must be maintained during the investigation.

