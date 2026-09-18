# Incident Response | SOC Investigation Portfolio

I document how I investigate and respond to security incidents in hands-on training environments. These case studies show my reasoning, the evidence I used, the response actions I would take, and the limits of what the available logs and screenshots can prove.

The repository contains **three separate simulated scenarios**. The numbered files are a reading order, not one continuous incident.

## Case studies

### SwiftSpend Financial — incident response lifecycle

| Part | Focus |
| --- | --- |
| [01 — Incident Response Case Study](doc/01%20-%20Incident%20Response%20Case%20Study.md) | Preparation, asset visibility, logging, and response roles. |
| [02 — Identification and Scoping](doc/02%20-%20Identification%20and%20Scoping.md) | Alert assessment, evidence gathering, and scope. |
| [03 — Containment and Threat Intelligence](doc/03%20-%20Containment%20and%20Threat%20Intelligence.md) | Containment decisions and indicator enrichment. |
| [04 — Eradication and Remediation](doc/04%20-%20Eradication%20and%20Remediation.md) | Jenkins investigation, remediation, and recovery planning. |

### Phishing Unfolding — SOC investigation

| Case | Focus |
| --- | --- |
| [05 — Phishing Unfolding SOC Investigation](doc/05%20-%20Phishing%20Unfolding%20SOC%20Investigation.md) | Phishing triage and endpoint investigation using SIEM and Sysmon evidence. |

I place the screenshots beside the findings they support. The [evidence index](evidence/phishing-unfolding/README.md) provides timestamp-based navigation for this case.

### Nexus Financial — incident response lab

| Part | Focus |
| --- | --- |
| [06 — Preparation](doc/06%20-%20Preparation.md) | People, processes, assets, logging, and detection readiness. |
| [07 — Detection and Analysis](doc/07%20-%20Detection%20and%20Analysis%20-%20Evidence%20Integrated.md) | Validate the SOC escalation, trace phishing and account activity, and establish scope. |
| [08 — Recovery and Validation](doc/08%20-%20Recovery%20and%20Validation.md) | Investigate mailbox rules, internal phishing, and SharePoint downloads; define containment and recovery checks. |
| [09 — Post-Incident Activity and Lessons Learned](doc/09%20-%20Post-Incident%20Activity%20and%20Lessons%20Learned%20-%20Final.md) | Reconstruct the timeline, review control gaps, and turn findings into response improvements. |

These four write-ups follow the Nexus Financial training incident from preparation through the lessons learned. I use the screenshots and logs available in each room to support the analysis.

## How I present the evidence

- Screenshots appear inline at the relevant observations so the investigation can be read on GitHub without opening separate image links.
- I distinguish observed events from my interpretation and proposed response actions.
- A search result or screenshot does not, by itself, prove data exfiltration, successful containment, or complete recovery. I state those limits where they affect a conclusion.

All company names, identities, and environments shown in the lab material belong to training simulations. The write-ups are my own analysis of those exercises.
