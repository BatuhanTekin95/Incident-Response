# Phishing Unfolding — SOC Investigation

## Case overview

This case study documents an investigation in the **Phishing Unfolding** SOC simulation. The available material consists of 65 screenshots captured on **8 and 12 September 2026**. The screenshot dates identify capture sessions; they do not, by themselves, prove that every image belongs to one continuous incident replay.

The screenshots show a queue of email and process alerts, SIEM searches, Sysmon events, and analyst classification examples. The most significant chain in the 12 September evidence starts with a suspicious invoice-themed email and includes a PowerShell command that references a downloaded remote-shell tool, local reconnaissance, access to a file share, file copying, and repeated DNS lookups. These observations support a **true-positive assessment of malicious endpoint activity** in the simulation. The screenshots alone do not prove that data left the environment.

### Complete screenshot walkthrough

All 65 screenshots from the source folder are displayed below in the report. The capture dates group the images; event timestamps inside each image may differ.

**Scenario overview**

![Phishing Unfolding scenario dashboard](../evidence/phishing-unfolding/overview.png)

#### 2026-09-08 — 33 screenshots

**Captured at 21:04:24**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:04:24](../evidence/phishing-unfolding/2026-09-08/210424.png)

**Captured at 21:06:05**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:06:05](../evidence/phishing-unfolding/2026-09-08/210605.png)

**Captured at 21:07:02**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:07:02](../evidence/phishing-unfolding/2026-09-08/210702.png)

**Captured at 21:08:48**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:08:48](../evidence/phishing-unfolding/2026-09-08/210848.png)

**Captured at 21:09:59**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:09:59](../evidence/phishing-unfolding/2026-09-08/210959.png)

**Captured at 21:13:42**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:13:42](../evidence/phishing-unfolding/2026-09-08/211342.png)

**Captured at 21:14:35**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:14:35](../evidence/phishing-unfolding/2026-09-08/211435.png)

**Captured at 21:15:58**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:15:58](../evidence/phishing-unfolding/2026-09-08/211558.png)

**Captured at 21:19:05**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:19:05](../evidence/phishing-unfolding/2026-09-08/211905.png)

**Captured at 21:20:18**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:20:18](../evidence/phishing-unfolding/2026-09-08/212018.png)

**Captured at 21:20:50**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:20:50](../evidence/phishing-unfolding/2026-09-08/212050.png)

**Captured at 21:21:11**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:21:11](../evidence/phishing-unfolding/2026-09-08/212111.png)

**Captured at 21:21:30**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:21:30](../evidence/phishing-unfolding/2026-09-08/212130.png)

**Captured at 21:21:50**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:21:50](../evidence/phishing-unfolding/2026-09-08/212150.png)

**Captured at 21:22:10**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:22:10](../evidence/phishing-unfolding/2026-09-08/212210.png)

**Captured at 21:22:31**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:22:31](../evidence/phishing-unfolding/2026-09-08/212231.png)

**Captured at 21:22:54**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:22:54](../evidence/phishing-unfolding/2026-09-08/212254.png)

**Captured at 21:23:22**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:23:22](../evidence/phishing-unfolding/2026-09-08/212322.png)

**Captured at 21:25:24**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:25:24](../evidence/phishing-unfolding/2026-09-08/212524.png)

**Captured at 21:28:48**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:28:48](../evidence/phishing-unfolding/2026-09-08/212848.png)

**Captured at 21:31:26**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:31:26](../evidence/phishing-unfolding/2026-09-08/213126.png)

**Captured at 21:33:21**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:33:21](../evidence/phishing-unfolding/2026-09-08/213321.png)

**Captured at 21:33:54**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:33:54](../evidence/phishing-unfolding/2026-09-08/213354.png)

**Captured at 21:34:17**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:34:17](../evidence/phishing-unfolding/2026-09-08/213417.png)

**Captured at 21:34:46**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:34:46](../evidence/phishing-unfolding/2026-09-08/213446.png)

**Captured at 21:35:20**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:35:20](../evidence/phishing-unfolding/2026-09-08/213520.png)

**Captured at 21:35:37**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:35:37](../evidence/phishing-unfolding/2026-09-08/213537.png)

**Captured at 21:36:10**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:36:10](../evidence/phishing-unfolding/2026-09-08/213610.png)

**Captured at 21:37:29**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:37:29](../evidence/phishing-unfolding/2026-09-08/213729.png)

**Captured at 21:38:07**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:38:07](../evidence/phishing-unfolding/2026-09-08/213807.png)

**Captured at 21:38:42**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:38:42](../evidence/phishing-unfolding/2026-09-08/213842.png)

**Captured at 21:39:25**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:39:25](../evidence/phishing-unfolding/2026-09-08/213925.png)

**Captured at 21:40:11**

![Phishing Unfolding screenshot captured on 2026-09-08 at 21:40:11](../evidence/phishing-unfolding/2026-09-08/214011.png)

#### 2026-09-12 — 31 screenshots

**Captured at 22:05:51**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:05:51](../evidence/phishing-unfolding/2026-09-12/220551.png)

**Captured at 22:09:07**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:09:07](../evidence/phishing-unfolding/2026-09-12/220907.png)

**Captured at 22:09:47**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:09:47](../evidence/phishing-unfolding/2026-09-12/220947.png)

**Captured at 22:11:33**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:11:33](../evidence/phishing-unfolding/2026-09-12/221133.png)

**Captured at 22:12:22**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:12:22](../evidence/phishing-unfolding/2026-09-12/221222.png)

**Captured at 22:13:20**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:13:20](../evidence/phishing-unfolding/2026-09-12/221320.png)

**Captured at 22:14:10**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:14:10](../evidence/phishing-unfolding/2026-09-12/221410.png)

**Captured at 22:14:24**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:14:24](../evidence/phishing-unfolding/2026-09-12/221424.png)

**Captured at 22:16:17**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:16:17](../evidence/phishing-unfolding/2026-09-12/221617.png)

**Captured at 22:17:02**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:17:02](../evidence/phishing-unfolding/2026-09-12/221702.png)

**Captured at 22:20:00**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:20:00](../evidence/phishing-unfolding/2026-09-12/222000.png)

**Captured at 22:20:57**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:20:57](../evidence/phishing-unfolding/2026-09-12/222057.png)

**Captured at 22:22:46**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:22:46](../evidence/phishing-unfolding/2026-09-12/222246.png)

**Captured at 22:23:30**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:23:30](../evidence/phishing-unfolding/2026-09-12/222330.png)

**Captured at 22:27:50**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:27:50](../evidence/phishing-unfolding/2026-09-12/222750.png)

**Captured at 22:29:05**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:29:05](../evidence/phishing-unfolding/2026-09-12/222905.png)

**Captured at 22:30:44**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:30:44](../evidence/phishing-unfolding/2026-09-12/223044.png)

**Captured at 22:31:32**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:31:32](../evidence/phishing-unfolding/2026-09-12/223132.png)

**Captured at 22:32:44**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:32:44](../evidence/phishing-unfolding/2026-09-12/223244.png)

**Captured at 22:33:51**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:33:51](../evidence/phishing-unfolding/2026-09-12/223351.png)

**Captured at 22:34:51**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:34:51](../evidence/phishing-unfolding/2026-09-12/223451.png)

**Captured at 22:36:00**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:36:00](../evidence/phishing-unfolding/2026-09-12/223600.png)

**Captured at 22:36:45**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:36:45](../evidence/phishing-unfolding/2026-09-12/223645.png)

**Captured at 22:37:38**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:37:38](../evidence/phishing-unfolding/2026-09-12/223738.png)

**Captured at 22:38:34**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:38:34](../evidence/phishing-unfolding/2026-09-12/223834.png)

**Captured at 22:39:36**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:39:36](../evidence/phishing-unfolding/2026-09-12/223936.png)

**Captured at 22:40:36**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:40:36](../evidence/phishing-unfolding/2026-09-12/224036.png)

**Captured at 22:41:25**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:41:25](../evidence/phishing-unfolding/2026-09-12/224125.png)

**Captured at 22:42:07**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:42:07](../evidence/phishing-unfolding/2026-09-12/224207.png)

**Captured at 22:42:51**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:42:51](../evidence/phishing-unfolding/2026-09-12/224251.png)

**Captured at 22:43:31**

![Phishing Unfolding screenshot captured on 2026-09-12 at 22:43:31](../evidence/phishing-unfolding/2026-09-12/224331.png)

## Scope and method

- **Primary data sources:** email alert details, SIEM searches, and Sysmon process, file-creation, and DNS events.
- **Primary host in the suspicious chain:** `win-3450`.
- **Related user context visible in paths and email events:** `michael.ascot`.
- **Additional host reviewed for comparison:** `win-3451`.
- **Evidence archive:** [all screenshots, ordered by capture time](../evidence/phishing-unfolding/README.md).

The analysis pivots from the email sender and attachment to the recipient's endpoint activity, then follows process ancestry and command lines through the share-access and DNS events. It separates an alert's rule name from what the underlying event actually establishes.

## Alert triage

The alert queue includes low-severity detections for mail from unusual external domains. Such a rule can produce both useful leads and noise. One screenshot records an invoice-themed message with a ZIP attachment, addressed to `michael.ascot@tryhatme.com`; the 12 September SIEM view shows the same sender and attachment pattern. The attachment and urgent payment language justify investigation, but the email record alone does not establish that the recipient opened or executed it. [Alert detail](../evidence/phishing-unfolding/2026-09-08/212130.png) · [SIEM email event](../evidence/phishing-unfolding/2026-09-12/221702.png)

Other screenshots show why alerts need event-level validation. An analyst note classifies a `TrustedInstaller.exe` parent-child alert as a false positive after reviewing its path and related activity. `taskhostw.exe` with `KEYROAMING` under `svchost.exe` is also inspected as a comparison point; its rule name alone is not evidence of compromise. [False-positive rationale](../evidence/phishing-unfolding/2026-09-08/211905.png) · [Taskhost search](../evidence/phishing-unfolding/2026-09-12/221222.png)

## Observed sequence on 12 September

Times below are the event timestamps displayed in the screenshots, not the screenshot capture times.

| Lab event time | Observation | Supporting evidence |
| --- | --- | --- |
| 21:02 | An inbound, overdue-payment message carries the ZIP attachment. | [Email event](../evidence/phishing-unfolding/2026-09-12/221702.png) |
| Before 21:22 | The user context has Outlook activity involving a locally cached `.eml` file named like a pending invoice. This is a useful pivot, but the screenshot does not link that file conclusively to the ZIP attachment. | [Outlook and file events](../evidence/phishing-unfolding/2026-09-12/222000.png) |
| 21:22:21 | PowerShell starts with a command line that downloads `powercat.ps1` and specifies a remote relay. This is much stronger evidence than the email's appearance alone. | [Process timeline](../evidence/phishing-unfolding/2026-09-12/223044.png) |
| 21:22–21:23 | The same PowerShell process launches `systeminfo.exe`, `whoami.exe`, and `net.exe` queries; a `PowerView.ps1` file-creation event appears. These are consistent with discovery activity. | [Child-process and file events](../evidence/phishing-unfolding/2026-09-12/223351.png) |
| 21:25–21:26 | `net.exe` maps `Z:` to `\\FILESRV-01\SSF-FinancialRecords`. `Robocopy.exe` then copies from its `Z:\` working directory into a local `downloads\exfiltration` folder; the drive mapping is subsequently removed. | [Share and copy events](../evidence/phishing-unfolding/2026-09-12/222750.png) |
| 21:27 | Multiple `nslookup.exe` processes run from the local exfiltration folder with long subdomains under `haz4rdw4re.io`. The pattern is consistent with attempted DNS-based data transfer, although these images do not show transfer success or volume. | [Process table](../evidence/phishing-unfolding/2026-09-12/222905.png) |

The SIEM searches use `host.name`, `datasource=sysmon`, process names, parent PIDs, command lines, and file paths to connect events. The linked process tables are more reliable than treating every low-severity alert as a separate confirmed incident. [PowerShell and DNS pivot](../evidence/phishing-unfolding/2026-09-12/222330.png) · [Process ancestry](../evidence/phishing-unfolding/2026-09-12/223351.png)

## Assessment

The PowerShell command, reconnaissance child processes, mapped file share, local copying, and repeated encoded-looking DNS lookups form a coherent suspicious sequence on `win-3450`. This merits escalation as a **simulated true-positive endpoint incident** and investigation of possible data exposure. The visible `PowerView.ps1` and `powercat.ps1` references strengthen that assessment, but the source files, network payloads, and destination-side records are not available here.

The original screenshots do **not** establish:

- Whether the suspicious ZIP was opened or caused the later endpoint activity.
- Whether the remote relay connection was established.
- Whether the copied files were successfully sent over DNS or another channel.
- Whether containment, credential reset, or recovery was completed.

## Indicators and hunting pivots

These values come from the simulated evidence and should be interpreted in context. Shared services and common tools are not suitable for blanket blocking based on one screenshot.

| Type | Value or pattern | Use |
| --- | --- | --- |
| Sender domain | `hatmakereurope.xyz` | Find matching messages and recipients. |
| Attachment | Invoice-themed ZIP in the linked email event | Correlate email, download, and file events. |
| Endpoint | `win-3450` | Review process tree, file creation, authentication, and network telemetry. |
| Local staging path | `downloads\exfiltration` | Search file creation, copy, and archive activity. |
| File share | `\\FILESRV-01\SSF-FinancialRecords` | Review share access and affected files. |
| DNS pattern | Long labels under `haz4rdw4re.io` | Correlate DNS queries with process and network logs. |
| Tool references | `powercat.ps1`, `PowerView.ps1` | Check file hashes, acquisition, and execution details. |
| Remote relay | `2.tcp.ngrok.io` in the PowerShell command | Investigate the exact connection and timing; the hostname is shared infrastructure. |

## Recommended response and validation

1. Preserve the relevant email, endpoint, DNS, proxy, file-share, and authentication logs with their timestamps and time-zone context.
2. Isolate `win-3450` according to the lab response procedure and capture volatile evidence before changing the host, if still available.
3. Identify files read from `SSF-FinancialRecords`, compare their hashes to local staging files, and check network or DNS logs for confirmed outbound transfer.
4. Review the recipient account's recent sign-ins and access, then rotate credentials and revoke sessions if compromise is confirmed.
5. Hunt for the same sender, attachment, process command-line patterns, staging path, and DNS pattern across other hosts.
6. Tune the low-severity mail and process rules using validated false positives without suppressing the stronger correlated chain.

These are proposed actions derived from the screenshot evidence; the archive does not show that they were performed.

## Evidence inventory

All **65** source images are displayed individually in the **Case overview** above: a scenario overview, 33 captures from 8 September, and 31 captures from 12 September. The [screenshot index](../evidence/phishing-unfolding/README.md) provides timestamp-based navigation. The images were copied without editing.
