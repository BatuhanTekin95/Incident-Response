# Phishing Unfolding — SOC Investigation

## Case overview

This case study documents an investigation in the **Phishing Unfolding** SOC simulation. The available material consists of 65 screenshots captured on **8 and 12 September 2026**. The screenshot dates identify capture sessions; they do not, by themselves, prove that every image belongs to one continuous incident replay.

The screenshots show a queue of email and process alerts, SIEM searches, Sysmon events, and analyst classification examples. The most significant chain in the 12 September evidence starts with a suspicious invoice-themed email and includes a PowerShell command that references a downloaded remote-shell tool, local reconnaissance, access to a file share, file copying, and repeated DNS lookups. These observations support a **true-positive assessment of malicious endpoint activity** in the simulation. The screenshots alone do not prove that data left the environment.

![Phishing Unfolding scenario dashboard](../evidence/phishing-unfolding/overview.png)

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

## Alert-by-alert evidence

Each alert below places its original alert card and the relevant supporting screenshots next to the assessment. Some SIEM views support multiple alerts and are repeated where needed. Capture times label the images; event timestamps are shown inside them.

### Alert 1000 — Suspicious email from an external domain

**Finding:** An inbound message from `trendymillineryco.me` has no attachment. The SIEM also shows an outbound message to that domain; the reputation screenshot reports no vendor detections at that time.

**Assessment:** Low-confidence phishing lead. The provided evidence does not show a malicious attachment, click, or follow-on endpoint activity for this message.

**Evidence**

**Alert detail — captured 2026-09-08 21:04:24**

![Alert 1000: Alert detail](../evidence/phishing-unfolding/2026-09-08/210424.png)

**Inbound email event — captured 2026-09-08 21:06:05**

![Alert 1000: Inbound email event](../evidence/phishing-unfolding/2026-09-08/210605.png)

**Inbound and outbound email search — captured 2026-09-08 21:07:02**

![Alert 1000: Inbound and outbound email search](../evidence/phishing-unfolding/2026-09-08/210702.png)

**Domain reputation check — captured 2026-09-08 21:08:48**

![Alert 1000: Domain reputation check](../evidence/phishing-unfolding/2026-09-08/210848.png)

**Case-report form; not independent proof — captured 2026-09-08 21:09:59**

![Alert 1000: Case-report form; not independent proof](../evidence/phishing-unfolding/2026-09-08/210959.png)

**SIEM copy of the inbound message — captured 2026-09-12 22:09:07**

![Alert 1000: SIEM copy of the inbound message](../evidence/phishing-unfolding/2026-09-12/220907.png)

**SIEM sender-domain search — captured 2026-09-12 22:09:47**

![Alert 1000: SIEM sender-domain search](../evidence/phishing-unfolding/2026-09-12/220947.png)

### Alert 1001 — TrustedInstaller parent-child relationship

**Finding:** On `win-3459`, `services.exe` starts `TrustedInstaller.exe` from the expected Windows servicing path. The analyst report records a false-positive rationale after checking the process context.

**Assessment:** False positive on the evidence shown; no suspicious child process is demonstrated.

**Evidence**

**Alert detail — captured 2026-09-08 21:13:42**

![Alert 1001: Alert detail](../evidence/phishing-unfolding/2026-09-08/211342.png)

**Sysmon process event — captured 2026-09-08 21:14:35**

![Alert 1001: Sysmon process event](../evidence/phishing-unfolding/2026-09-08/211435.png)

**Parent PID search — captured 2026-09-08 21:15:58**

![Alert 1001: Parent PID search](../evidence/phishing-unfolding/2026-09-08/211558.png)

**Analyst false-positive report — captured 2026-09-08 21:19:05**

![Alert 1001: Analyst false-positive report](../evidence/phishing-unfolding/2026-09-08/211905.png)

**SIEM TrustedInstaller search — captured 2026-09-12 22:11:33**

![Alert 1001: SIEM TrustedInstaller search](../evidence/phishing-unfolding/2026-09-12/221133.png)

### Alert 1002 — taskhostw.exe KEYROAMING

**Finding:** `svchost.exe` starts `taskhostw.exe KEYROAMING` on `win-3451`; the SIEM returns the matching event.

**Assessment:** No malicious follow-on activity is shown for this process event. Validate the executable path and signature before closing a live alert.

**Evidence**

**Alert detail — captured 2026-09-08 21:20:18**

![Alert 1002: Alert detail](../evidence/phishing-unfolding/2026-09-08/212018.png)

**SIEM taskhostw events on win-3451 — captured 2026-09-12 22:12:22**

![Alert 1002: SIEM taskhostw events on win-3451](../evidence/phishing-unfolding/2026-09-12/221222.png)

### Alert 1003 — External-domain email to yani.zubair

**Finding:** The message from `fashionindustrytrends.xyz` is an inbound hat-marketing email without an attachment. A later SIEM search finds the same sender; the domain reputation view is mixed and not conclusive.

**Assessment:** The screenshot supports mail triage, not endpoint compromise. Review message links and interaction logs before escalation.

**Evidence**

**Alert detail — captured 2026-09-08 21:20:50**

![Alert 1003: Alert detail](../evidence/phishing-unfolding/2026-09-08/212050.png)

**SIEM sender search — captured 2026-09-12 22:13:20**

![Alert 1003: SIEM sender search](../evidence/phishing-unfolding/2026-09-12/221320.png)

**Shared domain reputation context — captured 2026-09-12 22:16:17**

![Alert 1003: Shared domain reputation context](../evidence/phishing-unfolding/2026-09-12/221617.png)

### Alert 1004 — External-domain email to kyra.flores

**Finding:** A second inbound message from `fashionindustrytrends.xyz` has no attachment. The SIEM view includes this mail and outbound messages involving the same domain.

**Assessment:** Possible campaign-related mail; the provided screenshots do not establish a click, credential disclosure, or execution.

**Evidence**

**Alert detail — captured 2026-09-08 21:21:11**

![Alert 1004: Alert detail](../evidence/phishing-unfolding/2026-09-08/212111.png)

**Inbound message in SIEM results — captured 2026-09-12 22:14:10**

![Alert 1004: Inbound message in SIEM results](../evidence/phishing-unfolding/2026-09-12/221410.png)

**Outbound mail context — captured 2026-09-12 22:14:24**

![Alert 1004: Outbound mail context](../evidence/phishing-unfolding/2026-09-12/221424.png)

**Shared domain reputation context — captured 2026-09-12 22:16:17**

![Alert 1004: Shared domain reputation context](../evidence/phishing-unfolding/2026-09-12/221617.png)

### Alert 1005 — Suspicious invoice attachment

**Finding:** An urgent overdue-payment email to `michael.ascot@tryhatme.com` includes an invoice-themed ZIP. SIEM searches recover the email event and Outlook-related `.eml` activity.

**Assessment:** Escalate as a suspicious phishing email. The screenshots do not prove that this attachment was opened or caused the later PowerShell activity.

**Evidence**

**Alert detail and attachment — captured 2026-09-08 21:21:30**

![Alert 1005: Alert detail and attachment](../evidence/phishing-unfolding/2026-09-08/212130.png)

**Email event and attachment — captured 2026-09-12 22:17:02**

![Alert 1005: Email event and attachment](../evidence/phishing-unfolding/2026-09-12/221702.png)

**Outlook and cached email activity — captured 2026-09-12 22:20:00**

![Alert 1005: Outlook and cached email activity](../evidence/phishing-unfolding/2026-09-12/222000.png)

**Attachment-name search — captured 2026-09-12 22:20:57**

![Alert 1005: Attachment-name search](../evidence/phishing-unfolding/2026-09-12/222057.png)

### Alert 1006 — rdpclip.exe on win-3450

**Finding:** `svchost.exe` starts `rdpclip.exe` on `win-3450`. One broader host view includes other Sysmon activity; a targeted search confirms the `rdpclip.exe` event.

**Assessment:** The clipboard process event alone is not proof of compromise, even though later alerts on this host form a suspicious chain.

**Evidence**

**Alert detail — captured 2026-09-08 21:21:50**

![Alert 1006: Alert detail](../evidence/phishing-unfolding/2026-09-08/212150.png)

**Broader host event context — captured 2026-09-12 22:05:51**

![Alert 1006: Broader host event context](../evidence/phishing-unfolding/2026-09-12/220551.png)

**Targeted rdpclip.exe search — captured 2026-09-12 22:34:51**

![Alert 1006: Targeted rdpclip.exe search](../evidence/phishing-unfolding/2026-09-12/223451.png)

### Alert 1007 — Second taskhostw.exe KEYROAMING event

**Finding:** Another `taskhostw.exe KEYROAMING` event appears on `win-3451`, again under `svchost.exe`. The shared SIEM search shows both taskhostw events.

**Assessment:** No malicious relationship is established by these screenshots.

**Evidence**

**Alert detail — captured 2026-09-08 21:22:10**

![Alert 1007: Alert detail](../evidence/phishing-unfolding/2026-09-08/212210.png)

**SIEM taskhostw events on win-3451 — captured 2026-09-12 22:12:22**

![Alert 1007: SIEM taskhostw events on win-3451](../evidence/phishing-unfolding/2026-09-12/221222.png)

### Alert 1008 — WUDFHost.exe on win-3455

**Finding:** `services.exe` starts `WUDFHost.exe` from `C:\Windows\System32` with UMDF host parameters. The SIEM view shows the corresponding event.

**Assessment:** The displayed parent, path, and command line are consistent with Windows driver-host activity; the rule name alone is not enough to classify it as malicious.

**Evidence**

**Alert detail — captured 2026-09-08 21:22:31**

![Alert 1008: Alert detail](../evidence/phishing-unfolding/2026-09-08/212231.png)

**Shared WUDFHost.exe SIEM search — captured 2026-09-12 22:36:00**

![Alert 1008: Shared WUDFHost.exe SIEM search](../evidence/phishing-unfolding/2026-09-12/223600.png)

### Alert 1009 — rdpclip.exe on win-3453

**Finding:** A separate `rdpclip.exe` process is recorded under `svchost.exe` on `win-3453` and confirmed by a targeted SIEM search.

**Assessment:** No related malicious activity is visible in this evidence set.

**Evidence**

**Alert detail — captured 2026-09-08 21:22:54**

![Alert 1009: Alert detail](../evidence/phishing-unfolding/2026-09-08/212254.png)

**Targeted rdpclip.exe search — captured 2026-09-12 22:36:45**

![Alert 1009: Targeted rdpclip.exe search](../evidence/phishing-unfolding/2026-09-12/223645.png)

### Alert 1010 — Second WUDFHost.exe event

**Finding:** A second `WUDFHost.exe` process on `win-3455` is shown with Windows UMDF host parameters. The shared SIEM search contains both WUDFHost events.

**Assessment:** No malicious child activity or abnormal file path is shown here.

**Evidence**

**Alert detail — captured 2026-09-08 21:23:22**

![Alert 1010: Alert detail](../evidence/phishing-unfolding/2026-09-08/212322.png)

**Shared WUDFHost.exe SIEM search — captured 2026-09-12 22:36:00**

![Alert 1010: Shared WUDFHost.exe SIEM search](../evidence/phishing-unfolding/2026-09-12/223600.png)

### Alert 1011 — External-domain marketing email

**Finding:** An inbound message from `modernmillinerygroup.online` to `michael.ascot` advertises hat-enhancement pills and has no attachment; SIEM shows the corresponding message.

**Assessment:** Triage as suspicious or unwanted mail. The supplied evidence does not link it to the endpoint chain.

**Evidence**

**Alert detail — captured 2026-09-08 21:25:24**

![Alert 1011: Alert detail](../evidence/phishing-unfolding/2026-09-08/212524.png)

**SIEM sender-domain search — captured 2026-09-12 22:37:38**

![Alert 1011: SIEM sender-domain search](../evidence/phishing-unfolding/2026-09-12/223738.png)

### Alert 1012 — svchost.exe wsapp process

**Finding:** `services.exe` starts `svchost.exe -k wsapp -p` on `win-3459`. A targeted SIEM search confirms the same command line.

**Assessment:** No malicious follow-on action is shown in these screenshots.

**Evidence**

**Alert detail — captured 2026-09-08 21:28:48**

![Alert 1012: Alert detail](../evidence/phishing-unfolding/2026-09-08/212848.png)

**Targeted svchost.exe search — captured 2026-09-12 22:38:34**

![Alert 1012: Targeted svchost.exe search](../evidence/phishing-unfolding/2026-09-12/223834.png)

### Alert 1013 — Work-from-home scam email

**Finding:** The alert describes an inbound work-from-home offer from `hatventuresworldwide.online`. A later SIEM view shows the corresponding message.

**Assessment:** Suspicious mail, but no attachment, click, or endpoint effect is established here.

**Evidence**

**Alert detail — captured 2026-09-08 21:31:26**

![Alert 1013: Alert detail](../evidence/phishing-unfolding/2026-09-08/213126.png)

**Shared email search results — captured 2026-09-12 22:39:36**

![Alert 1013: Shared email search results](../evidence/phishing-unfolding/2026-09-12/223936.png)

### Alert 1014 — Bulk-hat offer email

**Finding:** An inbound bulk-hat offer from a Gmail sender has no attachment. The SIEM result reproduces the message to `liam.espinoza`.

**Assessment:** No evidence in the screenshots connects this email to the host compromise sequence.

**Evidence**

**Alert detail — captured 2026-09-08 21:33:21**

![Alert 1014: Alert detail](../evidence/phishing-unfolding/2026-09-08/213321.png)

**SIEM sender search — captured 2026-09-12 22:40:36**

![Alert 1014: SIEM sender search](../evidence/phishing-unfolding/2026-09-12/224036.png)

### Alert 1015 — TrustedInstaller.exe on win-3449

**Finding:** `services.exe` starts `TrustedInstaller.exe` from the Windows servicing path on another host; SIEM confirms the process event.

**Assessment:** Consistent with the benign TrustedInstaller pattern seen in Alert 1001; no suspicious child process is shown.

**Evidence**

**Alert detail — captured 2026-09-08 21:35:37**

![Alert 1015: Alert detail](../evidence/phishing-unfolding/2026-09-08/213537.png)

**Targeted TrustedInstaller.exe search — captured 2026-09-12 22:41:25**

![Alert 1015: Targeted TrustedInstaller.exe search](../evidence/phishing-unfolding/2026-09-12/224125.png)

### Alert 1016 — taskhostw.exe NGCKEYPREGEN

**Finding:** On `win-3456`, `taskhostw.exe NGCKEYPREGEN` runs under `svchost.exe`; SIEM returns the matching process record.

**Assessment:** The screenshot does not show malicious execution or follow-on activity from this event.

**Evidence**

**Alert detail — captured 2026-09-08 21:35:20**

![Alert 1016: Alert detail](../evidence/phishing-unfolding/2026-09-08/213520.png)

**Targeted taskhostw.exe search — captured 2026-09-12 22:42:07**

![Alert 1016: Targeted taskhostw.exe search](../evidence/phishing-unfolding/2026-09-12/224207.png)

### Alert 1017 — Another fashionindustrytrends.xyz email

**Finding:** The alert shows another no-attachment message from `fashionindustrytrends.xyz`. The domain reputation view provides shared context for Alerts 1003, 1004, and 1017.

**Assessment:** Treat the domain reputation as one supporting signal, not a final verdict on this individual message.

**Evidence**

**Alert detail — captured 2026-09-08 21:34:46**

![Alert 1017: Alert detail](../evidence/phishing-unfolding/2026-09-08/213446.png)

**Shared domain reputation context — captured 2026-09-12 22:16:17**

![Alert 1017: Shared domain reputation context](../evidence/phishing-unfolding/2026-09-12/221617.png)

### Alert 1018 — Prize-themed external email

**Finding:** A hat-themed prize message from `hatventuresworldwide.online` to `liam.espinoza` has no attachment. The same message is visible in the SIEM search results.

**Assessment:** Suspicious or unwanted email; no proven interaction or host impact in the available evidence.

**Evidence**

**Alert detail — captured 2026-09-08 21:33:54**

![Alert 1018: Alert detail](../evidence/phishing-unfolding/2026-09-08/213354.png)

**Shared email search results — captured 2026-09-12 22:39:36**

![Alert 1018: Shared email search results](../evidence/phishing-unfolding/2026-09-12/223936.png)

### Alert 1019 — taskhostw.exe KEYROAMING on win-3460

**Finding:** `svchost.exe` starts `taskhostw.exe KEYROAMING` on `win-3460`. SIEM confirms the command line and parent.

**Assessment:** No related malicious behavior is visible in the screenshots.

**Evidence**

**Alert detail — captured 2026-09-08 21:34:17**

![Alert 1019: Alert detail](../evidence/phishing-unfolding/2026-09-08/213417.png)

**Targeted taskhostw.exe search — captured 2026-09-12 22:42:51**

![Alert 1019: Targeted taskhostw.exe search](../evidence/phishing-unfolding/2026-09-12/224251.png)

### Alert 1020 — PowerView.ps1 created in Downloads

**Finding:** Sysmon records `PowerView.ps1` created by `powershell.exe` on `win-3450`. Searches around the same host show a PowerShell command referencing `powercat.ps1`, DNS activity, and discovery child processes.

**Assessment:** High-priority suspicious activity. The file-creation event proves the file was created; these screenshots do not independently prove PowerView execution or remote-shell connection success.

**Evidence**

**Alert detail and file path — captured 2026-09-08 21:36:10**

![Alert 1020: Alert detail and file path](../evidence/phishing-unfolding/2026-09-08/213610.png)

**Initial process and DNS search — captured 2026-09-12 22:22:46**

![Alert 1020: Initial process and DNS search](../evidence/phishing-unfolding/2026-09-12/222246.png)

**PowerShell DNS events — captured 2026-09-12 22:23:30**

![Alert 1020: PowerShell DNS events](../evidence/phishing-unfolding/2026-09-12/222330.png)

**PowerShell command and process timeline — captured 2026-09-12 22:30:44**

![Alert 1020: PowerShell command and process timeline](../evidence/phishing-unfolding/2026-09-12/223044.png)

**PowerView.ps1 file-creation event — captured 2026-09-12 22:32:44**

![Alert 1020: PowerView.ps1 file-creation event](../evidence/phishing-unfolding/2026-09-12/223244.png)

**PowerShell child processes and file activity — captured 2026-09-12 22:33:51**

![Alert 1020: PowerShell child processes and file activity](../evidence/phishing-unfolding/2026-09-12/223351.png)

### Alert 1021 — taskhostw.exe KEYROAMING on win-3451

**Finding:** A later `taskhostw.exe KEYROAMING` event appears on `win-3451` and is confirmed by a targeted SIEM search.

**Assessment:** No malicious behavior is established by this process event alone.

**Evidence**

**Alert detail — captured 2026-09-08 21:37:29**

![Alert 1021: Alert detail](../evidence/phishing-unfolding/2026-09-08/213729.png)

**Targeted taskhostw.exe search — captured 2026-09-12 22:43:31**

![Alert 1021: Targeted taskhostw.exe search](../evidence/phishing-unfolding/2026-09-12/224331.png)

### Alert 1022 — Network share mapped to Z:

**Finding:** A PowerShell child process runs `net.exe use Z:` to map `\\FILESRV-01\SSF-FinancialRecords` on `win-3450`. The SIEM process table also shows the later copy and unmap events.

**Assessment:** Suspicious in the context of the following staging and DNS activity; the mapping command alone could be legitimate.

**Evidence**

**Alert detail and net use command — captured 2026-09-08 21:38:07**

![Alert 1022: Alert detail and net use command](../evidence/phishing-unfolding/2026-09-08/213807.png)

**Correlated share-map and copy timeline — captured 2026-09-12 22:27:50**

![Alert 1022: Correlated share-map and copy timeline](../evidence/phishing-unfolding/2026-09-12/222750.png)

### Alert 1023 — Robocopy from mapped share

**Finding:** `Robocopy.exe` runs with `Z:\` as its working directory and a local `downloads\exfiltration` destination. Additional file events show local staging and a ZIP file.

**Assessment:** Strong evidence of collection or staging; the screenshots do not establish outbound transfer success.

**Evidence**

**Alert detail and Robocopy command — captured 2026-09-08 21:38:42**

![Alert 1023: Alert detail and Robocopy command](../evidence/phishing-unfolding/2026-09-08/213842.png)

**Correlated Robocopy process table — captured 2026-09-12 22:27:50**

![Alert 1023: Correlated Robocopy process table](../evidence/phishing-unfolding/2026-09-12/222750.png)

**Local staging and ZIP file events — captured 2026-09-12 22:31:32**

![Alert 1023: Local staging and ZIP file events](../evidence/phishing-unfolding/2026-09-12/223132.png)

### Alert 1024 — Mapped drive disconnected

**Finding:** `net.exe use Z: /delete` runs after the map-and-copy sequence on `win-3450`; the SIEM timeline shows its place in the chain.

**Assessment:** This strengthens the sequence but is not malicious by itself.

**Evidence**

**Alert detail and unmap command — captured 2026-09-08 21:39:25**

![Alert 1024: Alert detail and unmap command](../evidence/phishing-unfolding/2026-09-08/213925.png)

**Correlated drive-disconnect timeline — captured 2026-09-12 22:27:50**

![Alert 1024: Correlated drive-disconnect timeline](../evidence/phishing-unfolding/2026-09-12/222750.png)

### Alert 1025 — Repeated nslookup from staging folder

**Finding:** `nslookup.exe` processes are launched by PowerShell from `downloads\exfiltration` with long labels under `haz4rdw4re.io`.

**Assessment:** Consistent with attempted DNS-based exfiltration. DNS response and destination-side records are needed to confirm transfer and volume.

**Evidence**

**Alert detail and encoded-looking query — captured 2026-09-08 21:40:11**

![Alert 1025: Alert detail and encoded-looking query](../evidence/phishing-unfolding/2026-09-08/214011.png)

**Multiple nslookup process events — captured 2026-09-12 22:29:05**

![Alert 1025: Multiple nslookup process events](../evidence/phishing-unfolding/2026-09-12/222905.png)

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

All **65** source images are displayed inline: the scenario overview above, followed by the alert cards and their supporting evidence under each alert. Shared SIEM views may appear under more than one alert. The [screenshot index](../evidence/phishing-unfolding/README.md) provides timestamp-based navigation. The images were copied without editing.
