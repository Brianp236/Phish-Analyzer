<!-- Stage 5 output from the run against the red team's phishing email, reproduced as written. -->

# Fake Zoom update email delivered an unsigned, packed executable

## Summary
A phishing email titled "IMPORTANT ZOOM UPDATE", sent from a Proton Mail address posing as a regional water IT team, linked to a LimeWire download of a fake Zoom updater (`link_Zoom_update.exe`). The file is packed, carries an invalid Authenticode signature, and 18 VirusTotal engines flag it as malicious. In the sandbox it showed anti-analysis behaviour and tried one connection to a dead IP:Port. The email was purged from Gmail and quarantined, and a stub was delivered.

## What happened
1. **Email access:** The message "IMPORTANT ZOOM UPDATE" from `Regi0nalWaterIT@proton.me` was received. SPF, DKIM and DMARC all passed. Triage scored it 11 and rated it malicious.
2. **Static analysis:** The pipeline downloaded `link_Zoom_update.exe` (701,017 bytes) from the LimeWire link using a browser. No YARA rules matched. VirusTotal showed 18 malicious engines. The file is a PE with TLS callbacks, an unknown section name suggesting packing, an overlay, and an invalid Authenticode signature.
3. **Dynamic analysis:** CAPE task 29 returned a malscore of 1.9. The sample used anti-debug and anti-analysis techniques and exited soon after checking the local time. It attempted one connection to a dead IP:Port. The guest had no network access, so this is an attempt only.
4. **Action:** The email was purged from Gmail and quarantined, and a stub was delivered. The overall verdict is malicious.

## Why it was flagged
- Triage findings: file sharing link, link text/brand mismatch, urgency, download lure, and freemail impersonation (score 11, verdict malicious).
- The sender display name "Regi0nalWaterIT" uses a zero in place of the letter "o" and is sent from a free Proton Mail account. The theme (a Zoom update) does not match the claimed sender.
- Email authentication passing only shows the mail came from the real proton.me domain. It says nothing about whether the content is safe.
- VirusTotal: 18 engines flagged the payload as malicious.
- The file is packed and its Authenticode signature is invalid, which is unusual for a genuine Zoom installer.
- CAPE showed several anti-analysis signatures, including TLS callbacks that run before the entry point.
- No YARA rule matched, and the malware family is unknown.

## Sandbox behaviour
The CAPE malscore was low (1.9), and the sample may have exited early (see `stealth_timeout`). Its full behaviour is therefore not known.

| ATT&CK ID | Technique | What it means here |
|---|---|---|
| T1027 | Obfuscated Files or Information | The binary has an unknown PE section name that suggests packing, and it carries an overlay. |
| T1027.002 | (name not provided) | Listed by the pipeline without a name. It is likely related to the packing signatures. |
| T1036 | Masquerading | The file is named as a Zoom update but is not a genuine one. |
| T1055 | Process Injection | Mapped by the pipeline. The detail does not say how injection was used. |
| T1071 | Application Layer Protocol | The sample tried to connect to a dead IP:Port. No host or domain was recorded, and no connection succeeded. |
| T1553 | Subvert Trust Controls | The file carries an invalid Authenticode signature. |
| T1553.002 | (name not provided) | Listed by the pipeline without a name. It is likely related to the invalid signature. |

Other observed behaviour: SetUnhandledExceptionFilter (possible anti-debug), TLS callbacks running before the entry point, and a possible date-expiration check that made the sample exit quickly.

## Indicators of compromise
| Type | Value |
|---|---|
| Sender address | Regi0nalWaterIT@proton.me |
| Email subject | IMPORTANT ZOOM UPDATE |
| URL | hxxps://limewire[.]com/d/jihTz  (key removed) |
| File name | link_Zoom_update.exe |
| SHA-256 | b82603eda067f7579d91515c45f2a3c8c3343289621a41fa60a68d4eb1af72b8 |
| File size | 701,017 bytes |
| Network (sandbox) | No domains or hosts recorded. One dead IP:Port connection attempt (address unknown). |

## Actions taken
- Purged the email from Gmail.
- Quarantined the email.
- Delivered a stub.
- Case ID: Q-20261015-0002 (analysed 2026-10-15).

## Recommendations
- Check whether any other users received email from `Regi0nalWaterIT@proton.me` or the LimeWire link, and purge those messages.
- Search endpoint and proxy logs for the SHA-256, the file name `link_Zoom_update.exe`, and requests to the LimeWire URL, to find anyone who downloaded or ran the file. Isolate and review any host where it ran.
- Consider blocking the sender address and flagging LimeWire download links in inbound mail.
- Re-run the sample with controlled network access or a longer runtime, since it exited early and its full behaviour and command-and-control details are unknown.
- Remind users that Zoom updates come only from the Zoom client or zoom.us, and that passing SPF, DKIM and DMARC does not make an email trustworthy.

---
_Written by Claude via Claude Code from analyzer log events. Verify before acting._
