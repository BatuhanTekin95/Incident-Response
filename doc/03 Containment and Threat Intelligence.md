# Containment and Threat Intelligence

## Overview

Containment is a crucial phase of incident response. The main aim is to minimise the damage caused by an incident and prevent the adversary from affecting additional systems.

Containment also allows the incident response team to preserve evidence for forensic analysis. Once the threat has been contained, the team can begin eradication and recovery activities.

## Pre-Containment Investigation

Before taking containment action, the incident response team should collect as much information as possible about the incident.

Evidence can be collected from systems such as:

* Intrusion Detection Systems
* SIEM platforms
* Endpoint monitoring tools
* Network traffic monitoring systems
* Firewalls
* Proxy logs

This evidence can be used to identify Indicators of Compromise and Indicators of Attack.

For example, network traffic in ELK and Packetbeat may show that a workstation downloaded a suspicious executable. The affected workstation can then be investigated to collect additional evidence.

## File Hash Analysis

A file hash can be used to identify the same malicious file across multiple systems.

### Windows

```powershell
Get-FileHash dropper.exe
```

### Linux

```bash
sha256sum dropper.exe
```

Example SHA-256 hash provided in the room:

```text
463f1b1e11d4ca4c7a0c9aac540513ff7e681d9e5144bda2af24b86e438d3f4f
```

Any endpoint containing a file with this hash can be considered potentially compromised and should be investigated.

The hash can also be added to detection rules in a SIEM or endpoint security platform. The same process can be applied to suspicious IP addresses, domains and file names.

## Containment Strategies

Containment connects the identification and scoping phases with eradication and recovery.

The selected strategy depends on the severity of the incident, the available information and the risk of allowing the adversary to continue operating.

## Entire Isolation

Full isolation involves completely separating the compromised system from the rest of the environment.

This can be performed through:

* Network isolation
* Network segmentation
* Disabling switch ports
* Disconnecting network cables
* Disabling wireless access
* Physical isolation

Full isolation is an aggressive but effective containment strategy. It can stop lateral movement, command-and-control communication, malware propagation and data exfiltration.

However, the adversary may notice that access to the compromised system has been lost. They may then attempt to complete their objectives quickly or move to another compromised system that has not yet been identified.

Before using full isolation, the incident response team should consider:

* How aggressive the isolation should be
* Whether the adversary may perform destructive actions
* Whether other compromised systems have been identified
* Whether enough information has been collected about the adversary
* Whether immediate isolation is more important than intelligence collection

## Controlled Isolation

Controlled isolation is a less aggressive containment strategy.

Instead of completely disconnecting the compromised system, the incident response team continues monitoring the adversary while limiting their access.

The purpose is to collect more information about:

* Persistence mechanisms
* Lateral movement
* Command-and-control infrastructure
* Tools and malware
* Targeted systems
* Data access
* Adversary TTPs

The adversary should not be allowed to operate without restrictions. The incident response team must be prepared to block access before destructive activity, file deletion or data exfiltration takes place.

A cover story, such as planned maintenance, can be used when access needs to be restricted without informing the adversary that they have been detected.

Before using controlled isolation, the team should consider:

* The risk of allowing the adversary to continue
* Whether enough information has already been collected
* Whether the environment can be monitored continuously
* Whether the team can stop destructive activity quickly
* Whether enough personnel and technical resources are available

## Full Isolation vs Controlled Isolation

| Strategy             | Main Purpose                                   | Advantage                                           | Risk                                                  |
| -------------------- | ---------------------------------------------- | --------------------------------------------------- | ----------------------------------------------------- |
| Entire Isolation      | Stop malicious activity immediately            | Quickly prevents further access and damage          | May alert the adversary                               |
| Controlled Isolation | Monitor the adversary and collect intelligence | Provides more information about adversary behaviour | Requires continuous monitoring and rapid intervention |

## Threat Intelligence and Containment

Threat intelligence supports containment decisions by providing information about the adversary's previous behaviour and likely objectives.

For example, if intelligence shows that a threat actor normally performs rapid data exfiltration, immediate isolation may be required.

If the adversary is still being investigated and the organisation can safely monitor their activity, controlled isolation may provide additional IOCs and information about their TTPs.

Containment is not only about disconnecting an infected system. The incident response team must balance operational impact, intelligence collection and the risk of further damage.


## Threat Intelligence

Threat intelligence is information that can be linked to a malicious actor or threat campaign.

Common forms of threat intelligence include:

* IP addresses
* File hashes
* Domains
* File names
* Malware and attacker tools
* Attack patterns
* Tactics, techniques and procedures

These indicators can be used to identify malicious activity, create detection rules and understand how an adversary operates.

## Tactics, Techniques and Procedures

### Tactics

Tactics describe the high-level objective of the threat actor.

Examples include:

* Data theft
* Credential theft
* Espionage
* Financial gain
* Service disruption
* Extortion
* Destruction of systems

### Techniques

Techniques describe how the adversary achieves their objective.

Examples include:

* Phishing
* Exploiting vulnerable software
* Credential dumping
* Privilege escalation
* Persistence
* Lateral movement
* Data exfiltration

### Procedures

Procedures describe the specific sequence of actions used by the adversary during an attack.

Example attack chain:

```text
Phishing
    ↓
Credential Theft
    ↓
Privileged Account Access
    ↓
Lateral Movement
    ↓
Sensitive Data Exfiltration
```

Understanding TTPs allows the incident response team to predict the adversary's possible next actions and select an appropriate containment strategy.

## Threat Intelligence Platforms

Threat intelligence platforms allow organisations and security analysts to collect, share and analyse threat information.

Examples include:

* OpenCTI
* AlienVault OTX
* DigitalSide Threat Intelligence
* ThreatFeeds.io

Threat intelligence feeds can be integrated with SIEM platforms to detect known malicious IP addresses, domains and file hashes.

They can also be used to compare current activity with previous threat campaigns and identify known adversary behaviour.

## Internal Threat Reporting

An organisation should have a clear process for reporting suspicious emails, links and attachments.

Users should report suspicious content through an approved security channel instead of forwarding potentially malicious attachments to other employees.

This reduces the risk of spreading malicious files inside the organisation.


## Threat Intelligence-Driven Containment

Threat intelligence supports the identification, scoping and containment phases of incident response.

Indicators such as IP addresses, domains, file names and file hashes can be used to identify whether activity is associated with a known threat actor or Advanced Persistent Threat.

If the adversary is known, published threat reports can provide information about:

* Previous campaigns
* Common attack methods
* Malware and tools
* Targeted systems
* Possible objectives
* Expected next actions

This information allows the incident response team to predict where the adversary may move next and secure those systems before they are compromised.

## Purpose of Containment

The objective of containment is to make it more difficult for the adversary to achieve their goals.

Containment can also provide additional time for the incident response team to:

* Investigate affected systems
* Identify additional compromised assets
* Collect threat intelligence
* Limit lateral movement
* Protect critical systems
* Prepare for eradication and recovery

The team must balance intelligence collection with the risk of allowing the adversary to continue operating.

Waiting too long may allow the adversary to steal data or damage systems. Acting too early may prevent the team from understanding the full scope of the incident.

## Importance of Incident Scoping

Removing malware or restoring one compromised system does not confirm that the incident has been resolved.

The adversary may still have access to:

* Other endpoints
* User accounts
* Privileged accounts
* Cloud services
* Network devices
* Persistence mechanisms

If the incident is not properly scoped, the organisation may restore one system while the adversary remains active elsewhere in the environment.

A better understanding of the adversary creates a more accurate incident scope. A more accurate scope allows the team to create a more effective containment strategy.

## Positive Feedback Loop

Threat intelligence, incident scoping and containment support each other throughout the incident response process.

```text
Threat Intelligence
        ↓
Better Identification
        ↓
More Accurate Scoping
        ↓
Effective Containment
        ↓
Additional Evidence and Intelligence
```

Information collected during containment can improve later phases such as eradication, recovery and lessons learned.

After the incident, the organisation should review whether:

* Existing monitoring detected the activity
* SIEM alerts contained too much noise
* Important indicators were missed
* The response team had enough visibility
* Containment actions were performed quickly enough
* Detection rules should be created or updated

Threat intelligence is an ongoing process and should continue after the incident has been closed.


## Practical Lab: Analysing Threat Intelligence

### Objective

In this lab, I analysed a packet capture to identify threat intelligence related to a compromised workstation.

My investigation focused on identifying:

- The adversary's IP address
- The downloaded executable
- The SHA-256 hash of the executable

### Packet Capture Analysis

I opened the packet capture in Wireshark and applied the following display filter:

```wireshark
http
```

The HTTP traffic showed that the internal workstation `172.16.1.151` sent the following request:

```text
GET /dropper.exe HTTP/1.1
```

The destination IP address of the request was:

```text
3.250.38.141
```

Based on this traffic, I identified `3.250.38.141` as the adversary infrastructure used to host the executable.

<img width="1347" height="414" alt="01-http-dropper-download png" src="https://github.com/user-attachments/assets/9a7833ce-5933-48ad-a5c6-ee3894738cc0" />

### Network Findings

| Indicator | Value |
|---|---|
| Potentially compromised workstation | `172.16.1.151` |
| Adversary IP address | `3.250.38.141` |
| Protocol | `HTTP` |
| Downloaded file | `dropper.exe` |
| HTTP request | `GET /dropper.exe HTTP/1.1` |

### File Hash Analysis

The downloaded executable was located on the Desktop.

I calculated the SHA-256 hash of the file with the following command:

```bash
sha256sum /home/ubuntu/Desktop/dropper.exe
```

The command returned:

```text
463f1b1e11d4ca4c7a0c9aac540513ff7e681d9e5144bda2af24b86e438d3f4f  /home/ubuntu/Desktop/dropper.exe
```

<img width="940" height="122" alt="02-dropper-sha256 png" src="https://github.com/user-attachments/assets/c0525bff-6724-471e-a962-b8eb1119638b" />

### Indicators of Compromise

| IOC Type | Value |
|---|---|
| IP address | `3.250.38.141` |
| File name | `dropper.exe` |
| SHA-256 | `463f1b1e11d4ca4c7a0c9aac540513ff7e681d9e5144bda2af24b86e438d3f4f` |

### Recommended Containment Actions

Based on the identified indicators, the incident response team could:

- Investigate and isolate the workstation `172.16.1.151`
- Block connections to `3.250.38.141`
- Search other endpoints for `dropper.exe`
- Search the environment for the identified SHA-256 hash
- Create SIEM or EDR detection rules for the IP address and file hash
- Review network logs for other systems that contacted the same IP address
- Preserve the executable for further malware and forensic analysis

### Conclusion

The packet capture showed that the internal workstation `172.16.1.151` requested `dropper.exe` from the public IP address `3.250.38.141`.

I also calculated the SHA-256 hash of the executable. The identified IP address, file name and file hash can be used to search for related activity, improve the scope of the incident and support containment actions.







