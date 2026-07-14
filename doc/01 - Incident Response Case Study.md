# Incident Response Case Study

## Introduction

This project covers the incident response lifecycle through a fictional financial organisation named **SwiftSpend Financial (SSF)**.

In this scenario, I took the role of an incident responder responsible for reviewing the organisation's security readiness and supporting the development of its incident response capability.

SSF had already implemented several basic security controls, including:

- Endpoint logging
- Centralised event log forwarding
- Network segmentation between departments
- PowerShell version 5 across its systems
- A basic detection infrastructure

However, the organisation had limited documentation regarding normal network and system activity. Incident response procedures, responsibilities, communication processes, and operational baselines had also not been fully established.

The project focuses on preparing the organisation to detect, investigate, contain, eradicate, and recover from security incidents through a structured and repeatable response process.

## Table of Contents

- [Incident Response Overview](#incident-response-overview)
- [Preparation](#preparing-the-incident-response-capability)
- [People and Documentation](#preparing-the-people)
- [Technology and Visibility](#preparing-the-technology)
- [Windows Event Logging Lab](#lab-restoring-windows-event-logging)
- [Atomic Red Team Validation](#validating-event-logging-with-atomic-red-team)
- [Sysmon Detection](#sysmon-file-creation-detection)
- [Local Security Policies](#reviewing-local-security-policies)
- [Lab Results](#preparation-lab-results)
- [Conclusion](#conclusion)

## Incident Response Overview

Incident response, also known as incident handling, is the structured process used to detect, investigate, manage, and recover from cybersecurity incidents.

An effective incident response capability combines:

- People
- Processes
- Technologies
- Documentation
- Communication procedures
- Forensic evidence handling
- Recovery planning

The primary objective is to reduce the impact of an attack, limit recovery time, preserve relevant evidence, and restore business operations safely.

## Security Event vs Security Incident

Before an investigation begins, it is important to distinguish between a security event and a confirmed security incident.

### Security Event

A security event is an observable occurrence within a system or network.

Examples include:

- A user connecting to a file server
- An employee sending an email
- A successful authentication
- Antivirus software blocking a suspicious file
- A PowerShell process being executed

A security event does not automatically indicate malicious activity. It may be part of normal system or user behaviour.

### Security Incident

A security incident is an event, or a group of related events, that violates security policies and negatively affects the confidentiality, integrity, or availability of organisational systems and data.

Examples include:

- Unauthorised system access
- Malware infection
- Ransomware encryption
- Data exfiltration
- Account compromise
- Denial-of-service activity

Clear incident classification and escalation criteria are required to determine when an event should be treated as a confirmed security incident.

## Incident Response Lifecycle

The incident response lifecycle provides a structured roadmap for managing security incidents from initial preparation to final recovery.

### 1. Preparation

Policies, procedures, tools, responsibilities, logging systems, communication channels, and response playbooks are established before an incident occurs.

### 2. Identification

Alerts and operational deviations are reviewed to determine whether they represent normal activity, a security event, or a confirmed incident.

### 3. Analysis and Scoping

The incident is investigated to determine:

- Which systems are affected
- How the attacker gained access
- Which accounts may be compromised
- What techniques were used
- What data may be at risk
- How far the activity has spread
- What impact the incident may have on the organisation

### 4. Containment

Affected systems are isolated to prevent further damage, malware propagation, or lateral movement.

Containment actions must also consider the preservation of logs, memory captures, disk images, and other forensic evidence.

### 5. Eradication

Malicious files, persistence mechanisms, compromised accounts, exploited vulnerabilities, and other adversarial artefacts are removed from the environment.

### 6. Recovery and Lessons Learned

Affected systems are restored to normal operation and monitored for signs of recurring malicious activity.

The incident is then reviewed to identify security gaps, improve procedures, update playbooks, and strengthen the organisation's future response capability.

## Incident Response Plan

An **Incident Response Plan (IRP)** is a formal document that defines how an organisation will respond to a cybersecurity incident.

The plan should cover:

- Incident definitions and severity levels
- Roles and responsibilities
- Escalation procedures
- Internal and external communication channels
- Evidence collection and preservation
- Legal and regulatory requirements
- Containment and recovery procedures
- Documentation requirements
- Incident response metrics

A documented response plan allows analysts, technical teams, management, legal departments, and other stakeholders to coordinate their actions during an incident.

Without established procedures, response decisions may become inconsistent, evidence may be lost, and attackers may remain active within the environment for longer periods.

## Incident Response Playbooks

Incident response playbooks provide specific actions and procedures for common incident types.

Examples include:

- Phishing
- Ransomware
- Malware infection
- Compromised user accounts
- Data exfiltration
- Insider threats
- Denial-of-service attacks

The main incident response plan defines the overall structure, responsibilities, and communication process. Playbooks provide detailed operational steps for identifying, containing, eradicating, and recovering from specific threats.

## Project Scope

The project follows the incident response lifecycle across the following areas:

1. Preparation
2. Identification and Scoping
3. Threat Intelligence
4. Containment
5. Eradication and Remediation
6. Recovery
7. Lessons Learned
8. Indicators of Compromise
9. MITRE ATT&CK Mapping
10. Final Incident Summary

## Preparing the Incident Response Capability

The preparation phase ensures that an organisation has the people, documentation, permissions, and procedures required to handle a security incident effectively.

For **SwiftSpend Financial (SSF)**, the preparation process focused on four main areas:

- Establishing an incident response team
- Training employees and technical personnel
- Preparing incident documentation
- Defining communication and response procedures

## Preparing the People

Employees are common targets for phishing and social engineering attacks. Incident preparation must therefore include both technical response personnel and general users across the organisation.

Employees should be able to recognise and report suspicious activity, while incident responders must have the technical knowledge required to investigate alerts, collect evidence, and coordinate response actions.

### Cyber Security Incident Response Team

A **Cyber Security Incident Response Team (CSIRT)** is responsible for managing events involving cybersecurity breaches.

The team should include individuals with different responsibilities and areas of expertise, such as:

- Incident responders
- SOC analysts
- System and network administrators
- Digital forensics specialists
- Legal representatives
- Public relations personnel
- Business and management representatives

Team members must have appropriate access permissions before an incident occurs. Privileged access should be controlled through established access control policies, and system administrators should be notified when elevated access is used during an investigation.

### Training and Assessment

Regular training and assessment sessions are required to prepare both employees and incident response personnel.

Employee awareness activities may include:

- Phishing awareness training
- Simulated phishing campaigns
- Social engineering exercises
- Procedures for reporting suspicious emails
- Guidance for handling unexpected attachments and links

Incident response personnel should also be familiar with:

- Reading and analysing audit logs
- Forensic imaging tools
- Evidence collection procedures
- Honeypots and vulnerable test systems
- Identifying suspicious system and network activity

Practical exercises allow the organisation to evaluate whether employees and responders can follow the established procedures during a real incident.

## Preparing the Documentation

Accurate documentation is required throughout the incident response process.

Incident records may later be used for:

- Forensic investigations
- Legal proceedings
- Regulatory reporting
- Incident reports
- Mitigation planning
- Lessons-learned reviews

Responders should document actions, timestamps, affected assets, collected evidence, investigation findings, and communication with relevant stakeholders.

## Security Policies

Security policies define the principles, responsibilities, and acceptable practices that apply during incident handling.

The organisation's policies should define:

- Acceptable use of organisational systems
- Prohibited activities
- Monitoring authority
- User privacy expectations
- Incident reporting requirements
- Evidence-handling responsibilities
- Access control requirements
- Escalation procedures

Policies should be visible and accessible to employees, users, and other relevant stakeholders.

They must also be reviewed by legal personnel to ensure compliance with applicable laws and regulations.

## Communication Plan

A communication plan identifies who must be contacted during an incident and defines how information should be shared.

The plan should include:

- Primary CSIRT contacts
- On-call response personnel
- Internal escalation paths
- Management notification procedures
- Legal and compliance contacts
- Law enforcement notification criteria
- Public relations and media procedures
- Third-party communication requirements

Communication records should be maintained throughout the investigation to track decisions, notifications, and the flow of incident-related information.

## Chain of Custody

Chain-of-custody documentation records how evidence is collected, transferred, stored, accessed, and analysed.

A chain-of-custody record should include:

- Description of the evidence
- Date and time of collection
- Name of the person who collected it
- Collection location
- Storage location
- Evidence transfers
- Names of individuals who handled the evidence
- Purpose of each transfer or access

Maintaining a complete chain of custody protects the integrity of the evidence and supports its use in legal or disciplinary proceedings.

## Response Procedures

Incident response procedures define the actions that personnel must follow when security defences are breached.

These procedures should be documented, approved by management, and regularly reviewed.

Effective response procedures should define:

1. How incidents are reported
2. How alerts are validated
3. Who has decision-making authority
4. When incidents should be escalated
5. How affected systems should be contained
6. How evidence should be preserved
7. How systems should be restored
8. How incident activities should be documented

Incident handling is an organisational responsibility. Technical teams, employees, management, legal personnel, and external stakeholders may all have a role in limiting damage and restoring normal business operations.

## Preparing the Technology

An effective incident response capability requires more than trained personnel and documented procedures. The CSIRT must also have visibility across the organisation’s infrastructure and access to the tools required for prevention, detection, investigation, containment, and recovery.

Technical preparation includes:

- Maintaining an accurate asset inventory
- Identifying high-value systems and data
- Collecting endpoint and network telemetry
- Deploying protective and detective security controls
- Segmenting critical parts of the network
- Preparing forensic investigation tools
- Establishing secure evidence storage

## Asset Inventory and Classification

The organisation must identify the systems, applications, devices, and data that support its business operations.

A complete asset inventory allows the CSIRT to determine:

- Which assets are present in the environment
- Where each asset is located
- Which operating system or software it uses
- Who owns or manages the asset
- How critical the asset is to business operations
- What type of data is stored or processed
- Which security controls should protect it

High-value assets may include:

- Critical servers
- Network infrastructure
- Cloud platforms
- Customer and employee data
- Intellectual property
- Business applications
- Authentication systems
- Financial records

Asset classification also supports incident prioritisation. An alert affecting a critical authentication server or a customer database may require a faster and more extensive response than an alert affecting a low-risk test system.

### Example Asset Inventory

| Asset Type | Asset Name | Operating System | IP Address |
|---|---|---|---|
| Mail Server | MailSrvr1 | Windows Server 2019 | 192.168.0.2 |
| Web Server | WebSrvr1 | Ubuntu Server 20.04 | 192.168.0.3 |
| VPN Server | VPN1 | Ubuntu Server 20.04 | 192.168.0.4 |
| Software | THM_MathBooks | Not applicable | Not applicable |
| Software | TruckFinder | Not applicable | Not applicable |

Hardware and software inventories should be maintained separately where necessary and updated whenever assets are added, modified, or removed.

## Technical Instrumentation

Once the organisation’s assets have been identified, telemetry must be collected from the infrastructure.

Relevant telemetry sources may include:

- Endpoint activity
- Authentication events
- Process creation logs
- PowerShell activity
- Network connections
- DNS requests
- Firewall events
- Email activity
- Cloud audit logs
- Application logs
- File access events

Security technologies used to collect or generate this information may include:

- Anti-malware solutions
- Endpoint Detection and Response systems
- Data Loss Prevention solutions
- Intrusion Detection and Prevention Systems
- Firewalls
- SIEM platforms
- Centralised log collectors
- Network monitoring tools

Centralised telemetry allows responders to correlate activity across multiple systems and reconstruct the sequence of events during an investigation.

## Network Segmentation

Network segmentation separates systems into logical groups based on their function, sensitivity, and access requirements.

Segmentation can be implemented through:

- Subnets
- VLANs
- Firewalls
- Access control rules
- Demilitarised zones
- IP-based restrictions

Critical systems should not be directly accessible from every part of the network.

Effective segmentation can:

- Reduce the attack surface
- Restrict unauthorised access
- Limit lateral movement
- Contain malware propagation
- Improve network monitoring
- Support faster isolation during an incident

For example, employee workstations, servers, administrative systems, and publicly accessible services should be placed in separate network zones with controlled communication between them.

## Incident Tracking and Case Management

Incident details should be recorded within a centralised case-management platform.

A case-management solution can be used to track:

- Incident status
- Severity
- Assigned responders
- Investigation tasks
- Collected observables
- Indicators of compromise
- Affected systems
- Evidence
- Analyst notes
- Response actions
- Important timestamps

Platforms such as **TheHive** can support collaboration between analysts and maintain a structured record of the investigation.

Case-management records should be updated throughout the incident to preserve a clear timeline of decisions, findings, and actions.

## Investigation Capabilities

The CSIRT must be able to investigate suspicious activity without relying on tools that are prepared only after an incident has already occurred.

Required investigation capabilities may include:

- Analysing endpoint and network logs
- Validating scripts and executable files
- Reviewing suspicious software installations
- Capturing system memory
- Creating forensic disk images
- Examining malicious files in a sandbox
- Monitoring network traffic
- Preserving collected evidence
- Reproducing attacker activity in an isolated environment

Forensic evidence should be stored in a secure location accessible only to authorised personnel.

The organisation should also verify that investigation tools are functional, licensed, updated, and available before they are required.

## Incident Response Jump Bag

A **jump bag** is a prepared kit containing tools and materials that incident responders may need during an investigation.

A jump bag may contain:

- External drives for evidence storage
- Write-protected media
- Disk-imaging tools
- Forensic software
- Network taps
- USB and SATA adapters
- Card readers
- Network cables
- PC repair tools
- Screwdrivers and tweezers
- Incident response forms
- Chain-of-custody documents
- Communication playbooks

The exact contents may vary depending on the organisation’s infrastructure and incident response responsibilities.

All equipment should be tested regularly and stored in a location that is accessible to authorised responders.


## Establishing Visibility

Incident responders require visibility across the organisation's digital assets before they can detect, investigate, and contain suspicious activity.

Visibility is established by collecting and reviewing information from internal and external sources, including:

- System and application logs
- Authentication records
- Network traffic
- Endpoint telemetry
- Threat intelligence feeds
- Vulnerability scan results
- Vendor security advisories
- Patch notifications
- Emerging adversary tactics, techniques, and procedures

Internal visibility provides information about activity occurring within the organisation's systems and network.

External visibility provides awareness of newly disclosed vulnerabilities, emerging threats, attacker behaviour, malicious signatures, and changes in the wider threat landscape.

Effective visibility allows the CSIRT to determine:

- Which resources were accessed
- When the activity occurred
- Which account or process performed the action
- Which systems were affected
- Whether the activity was authorised
- How the incident progressed through the environment

Collected telemetry also provides evidence for incident investigations, compliance reporting, mitigation planning, and post-incident reviews.

## Visibility Through Logs

Systems, applications, network devices, and security technologies generate logs that record activity within the environment.

A centralised **Security Information and Event Management (SIEM)** platform can collect, store, and correlate these records. This allows analysts to investigate activity across multiple data sources from a central location.

Logs must be protected against unauthorised modification and retained according to organisational, legal, and regulatory requirements.

### Common Log Types

#### Event Logs

Event logs record occurrences within a system or network, including:

- Login attempts
- Process execution
- Application activity
- Network connections
- File creation
- Service activity

#### Audit Logs

Audit logs provide a sequential record of actions performed within a system.

They may record:

- Who performed the action
- What action was performed
- When the action occurred
- Which resource was affected
- How the system responded
- Whether the action succeeded or failed

#### Error Logs

Error logs record problems that occur within systems and applications, including:

- Application failures
- Service failures
- Configuration errors
- Connection problems
- Hardware or software faults

#### Debug Logs

Debug logs contain detailed technical information generated during development, testing, and troubleshooting.

These logs may provide valuable context during an investigation, although they can generate a large volume of data and may contain sensitive application information.

## Common Log Sources

Incident response visibility should include multiple log sources from across the environment.

### Network Logs

Network logs may be collected from:

- Routers
- Switches
- Network sensors
- Packet-capture systems
- DNS servers

### Host Perimeter Logs

Host perimeter logs are commonly generated by:

- Firewalls
- Proxy servers
- VPN servers
- Web gateways

These logs may contain information about allowed and denied connections between internal systems and external networks.

### System Logs

System logs record operating-system activity, including:

- Authentication events
- Service activity
- Process execution
- File access
- Security policy changes
- Administrative actions

### Application Logs

Application logs may be generated by:

- Web applications
- Databases
- Cloud services
- Business applications
- Internal tools
- Authentication platforms

## Lab: Restoring Windows Event Logging

The practical investigation began by checking whether Windows Event Viewer could access and display system logs.

Event Viewer returned the following error:

```text
Event Log service is unavailable. Verify that the service is running.
```

This indicated that the Windows Event Log service was not running. Without this service, the system could not provide the required visibility for security monitoring and incident investigation.

<img width="783" height="548" alt="5d048288077c5f33c2015a5cf7b220f5" src="https://github.com/user-attachments/assets/3a69c67a-1a11-4bbb-a945-3609b375090d" />

### Inspecting the Event Log Registry Configuration

The Windows Event Log service configuration was reviewed through Registry Editor at the following location:

```text
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog
```

The `Start` registry value was configured as:

```text
Start = 4
```

A startup value of `4` indicated that the service was disabled.

<img width="1241" height="722" alt="Ekran görüntüsü 2026-07-14 220626" src="https://github.com/user-attachments/assets/359fafd3-acd3-4d6f-ba03-5d0a3dad83ab" />

### Enabling the Event Log Service

The `Start` registry value was changed from `4` to `2`.

```text
Start = 2
```

A startup value of `2` configures the Windows Event Log service to start automatically with the operating system.

<img width="859" height="438" alt="Ekran görüntüsü 2026-07-14 220712" src="https://github.com/user-attachments/assets/23411f20-df6b-4f82-8a98-2f91505fc55c" />

The virtual machine was restarted to apply the registry modification.

After the restart, Event Viewer opened successfully and began reading the available system logs. This confirmed that the Windows Event Log service had been restored.

<img width="1095" height="576" alt="Ekran görüntüsü 2026-07-14 222434" src="https://github.com/user-attachments/assets/4e1476fe-d061-4f7e-a676-84dabb3e922f" />

## Validating Event Logging with Atomic Red Team

After restoring the Windows Event Log service, an Atomic Red Team test was used to generate controlled activity and confirm that Sysmon was recording the expected events.

The following commands were executed in PowerShell:

```powershell
Invoke-AtomicTest T1486 -ShowDetailsBrief
Invoke-AtomicTest T1486-5
```

The output confirmed that the **T1486-5 PureLocker Ransom Note** test was executed successfully.

<img width="514" height="218" alt="Ekran görüntüsü 2026-07-14 222621" src="https://github.com/user-attachments/assets/f5a4fc13-ddfe-4180-86b4-bb4550c43a42" />

The selected test simulated activity associated with the following MITRE ATT&CK technique:

```text
T1486 — Data Encrypted for Impact
```

The test created the following file on the Administrator desktop:

```text
C:\Users\Administrator\Desktop\YOUR_FILES.txt
```

## Investigating the Sysmon Events

The generated activity was reviewed through the following Event Viewer path:

```text
Event Viewer
→ Applications and Services Logs
→ Microsoft
→ Windows
→ Sysmon
→ Operational
```

The file creation record was located by searching for:

```text
YOUR_FILES.txt
```

## Sysmon File Creation Detection

Sysmon recorded the ransom-note file creation through **Event ID 11**.

The event contained the following details:

| Field | Value |
|---|---|
| Event ID | `11` |
| Event Type | `File created` |
| Rule | `FileCreate` |
| Process | `C:\Windows\System32\cmd.exe` |
| Target File | `C:\Users\Administrator\Desktop\YOUR_FILES.txt` |
| User | `THM_AURORA_TEST\Administrator` |
| Log Source | `Microsoft-Windows-Sysmon/Operational` |

<img width="1335" height="752" alt="Sysmon Event ID 11 showing the creation of YOUR_FILES.txt" src="https://github.com/user-attachments/assets/b2ff8adc-6503-4f31-ae0b-933b7a1b79ae" />

The `TargetFilename` field confirmed that the process created the following file:

```text
C:\Users\Administrator\Desktop\YOUR_FILES.txt
```

The event was assigned to the following Sysmon category:

```text
File created (rule: FileCreate)
```

## Reviewing Local Security Policies

The final part of the preparation lab focused on reviewing security policies that affect application execution and authentication monitoring.

These configurations determine which software can run on the system and which logon activities are recorded for later investigation.

### Software Restriction Policies

The default software restriction level was reviewed through the following path:

```text
Local Security Policy
→ Software Restriction Policies
→ Security Levels
```

Three security levels were available:

- Disallowed
- Basic User
- Unrestricted

The default-policy indicator showed that the active security level was configured as:

```text
Unrestricted
```

<img width="660" height="474" alt="Ekran görüntüsü 2026-07-14 230056" src="https://github.com/user-attachments/assets/2b929493-cdb6-464a-9563-3c81f770fb82" />

An **Unrestricted** policy allows software to run according to the permissions of the user account.

Although this configuration provides operational flexibility, additional application-control policies may be required on sensitive systems to prevent unauthorised or untrusted software from executing.

### Audit Logon Events

The authentication auditing configuration was reviewed through:

```text
Local Security Policy
→ Local Policies
→ Audit Policy
→ Audit logon events
```

The policy was configured to record:

```text
Failure
```

<img width="783" height="562" alt="Ekran görüntüsü 2026-07-14 225405" src="https://github.com/user-attachments/assets/7e9b3223-40e0-481f-b1b4-02fb301607f1" />

This configuration records unsuccessful logon attempts.

Failed authentication events can provide useful evidence when investigating:

- Password guessing
- Brute-force attempts
- Use of invalid credentials
- Attempts to access disabled accounts
- Unauthorised access attempts

Successful logon auditing was not enabled within this policy configuration. Recording both successful and failed authentication activity can provide broader visibility when reconstructing account activity during an investigation.

## Preparation Phase Summary

The preparation phase establishes the organisational and technical foundation required to respond to cybersecurity incidents.

The main areas covered were:

### People

- Establishing a Cyber Security Incident Response Team
- Assigning technical, legal, business, and communication responsibilities
- Providing appropriate access permissions
- Conducting security-awareness and phishing training
- Preparing incident responders for forensic and log analysis

### Processes and Documentation

- Defining incident response policies
- Creating communication and escalation procedures
- Maintaining chain-of-custody documentation
- Developing incident response plans and playbooks
- Establishing structured response procedures

### Technology

- Maintaining hardware and software asset inventories
- Classifying critical organisational assets
- Deploying endpoint and network monitoring controls
- Collecting centralised telemetry
- Preparing forensic investigation tools
- Maintaining an incident response jump bag

### Visibility

- Collecting logs from endpoints, applications, firewalls, servers, and network devices
- Using SIEM and case-management platforms
- Monitoring external threat intelligence and security advisories
- Protecting logs against unauthorised modification
- Ensuring critical security services remain operational

## Preparation Lab Results

The practical configuration review identified and corrected a significant monitoring weakness.

| Item | Initial Observation | Result |
|---|---|---|
| Windows Event Log service | Disabled | Configured for automatic startup |
| Registry `Start` value | `4` | Changed to `2` |
| Event Viewer | Service unavailable | Operational after restart |
| Atomic Red Team validation | Not yet performed | `T1486-5` completed successfully |
| Sysmon file telemetry | Not yet validated | Event ID `11` identified |
| Created artefact | None before testing | `YOUR_FILES.txt` |
| Software restriction level | Reviewed | `Unrestricted` |
| Audit logon events | Reviewed | `Failure` |

The Windows Event Log service was restored, and the logging configuration was validated using controlled Atomic Red Team activity.

Sysmon successfully recorded the creation of the simulated ransom-note file through **Event ID 11**, confirming that file-creation telemetry was available for incident investigation.

## Conclusion

Incident response preparation requires coordinated implementation across people, processes, documentation, policies, and technology.

Training alone is not sufficient without clear procedures, and detection tools are not effective without reliable logging and visibility.

An organisation should therefore ensure that:

- Incident response responsibilities are defined
- Communication and escalation paths are documented
- Critical assets are inventoried and classified
- Security telemetry is collected and protected
- Authentication and endpoint activity are audited
- Response tools are available before an incident occurs
- Procedures and playbooks are regularly reviewed and tested

Frameworks such as the **NIST Computer Security Incident Handling Guide** provide structured guidance for developing and maintaining an incident response capability.

With the preparation phase completed, the next stages of the incident response lifecycle will focus on:

1. Identification
2. Analysis and Scoping
3. Containment
4. Eradication
5. Recovery
6. Lessons Learned



