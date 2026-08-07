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

## Key Takeaways

- Eradication should begin only after the incident has been properly scoped.
- Acting prematurely may alert the threat actor and cause further damage.
- Eradication and scoping operate as part of a continuous feedback loop.
- Initial remediation attempts may fail and require further investigation.
- Automated eradication is useful for known and less sophisticated threats.
- A complete system rebuild provides a clean slate but causes downtime.
- Targeted cleanup is suitable for critical systems but requires accurate threat intelligence.
- The final eradication method should balance security, system criticality, downtime, and business impact.

---

## Knowledge Check

**What may cause an attacker to believe that a complex eradication plan is already in motion?**

`Premature eradication`

**What informal term describes repeatedly finding and removing malicious activity across the environment?**

`Whack-a-mole`

**What is the first main goal of this phase?**

`Eradicate the bad guys`

**Which technique is most effective against less sophisticated threats using well-known malicious tooling?**

`Automated eradication`

**What is the most straightforward way to remove attacker traces from a system?**

`Complete system rebuild`

**What does a complete system rebuild entail for the affected system?**

`Downtime`

**The success of targeted system cleanup depends heavily on the quality of which process?**

`Scoping`

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

