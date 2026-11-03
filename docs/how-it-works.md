# How it works

Each run checks the inbox for new unread mail and takes every new email through five stages. This page
describes each part of the code and the decisions it makes.

| File | Role |
|---|---|
| `new_analyzer.py` | Main script: Gmail access, the five stages, verdicts, logging and the command-line options |
| `phish_triage.py` | Scores the email itself (headers, sender, links, wording, attachments) |
| `linkfetch.py` | Follows links and downloads the file behind them |
| `vault.py` | Quarantine, warning stub, release and chain of custody |
| `ai_report.py` | Incident report for each quarantined email |
| `display.py` | The five-stage terminal view (`--plain` turns it off) |

## Stage 1: Email Access

- Signs in to Gmail over IMAP with an OAuth 2.0 access token (XOAUTH2), refreshed from `oauth/token.json` when it
  expires. If the token is dead, the analyzer logs an `auth_failed` event and stops.
- Moves each new unread email to a `Pending` label, so it's out of the inbox while it's analyzed.
- Saves the raw email and records its SHA-256 as the first chain-of-custody entry (`intake`).

## Stage 2: Static Analysis

**Email triage (`phish_triage.py`).** Every finding adds points:

| Finding | Points |
|---|---|
| SPF / DKIM / DMARC fail | 2 / 2 / 3 |
| SPF or DKIM missing | 1 each |
| Display name spoofing a brand, lookalike domain | 3 each |
| Link text that doesn't match where the link goes (to another domain, or naming a brand) | 3 |
| Sender claims to be IT or a help desk but uses free webmail | 3 |
| Double file extension (`invoice.pdf.exe`) | 3 |
| Reply-To different from the sender | 2 |
| Link to a public file-sharing site, "download and open" wording, IP-address URL, punycode, `@` in a URL, risky attachment type | 2 each |
| Return-Path mismatch, URL shortener, urgency or deadline wording | 1 each |

A score of 4 or more is **suspicious**, and 8 or more is **malicious**.

**Link fetch (`linkfetch.py`).** Up to 5 links per email are followed (up to 5 redirects each), and any file
behind them is downloaded to the analyzer VM. It is saved but never opened.

- Share pages that only release the file after JavaScript runs, such as LimeWire, Google Drive or Dropbox, are
  opened in a headless Chromium. The browser dismisses cookie banners, clicks the "Download" button and catches
  the file. LimeWire keeps the decryption key after the `#` in the link, so the full link is used.
- Requests to private addresses (`127.x`, `10.x`, `172.16-31.x`, `192.168.x`, `100.64.x`) are blocked, so an
  email can't make the analyzer reach into the lab. Hosts can be allowed in `FETCH_ALLOW_HOSTS`.
- Files over 50 MB are refused. A screenshot of each page goes to `~/analyzer/link_screenshots/`.
- `LINKFETCH_HEADLESS=0` shows the browser window, and `DOWNLOAD_BUTTON_TEXT` sets which button labels it clicks.

**YARA (optional).** Each file is scanned with the rules in `~/analyzer/yara/`. A match makes the file at least
suspicious.

**VirusTotal.** The file's SHA-256 is looked up; the file itself is never uploaded, so nothing leaks to other
VirusTotal users. Five or more engines flagging it makes it malicious, and one to four makes it suspicious.

## Stage 3: Dynamic Analysis

Each file is submitted to CAPEv2 and run in the offline Windows 10 guest. The analyzer reads back the malscore,
the signatures and the MITRE ATT&CK techniques.

| Result | File verdict |
|---|---|
| 5+ VirusTotal engines, malscore 8 or more, or 2+ high-severity signatures | malicious |
| Malscore 5 or more, any high-severity signature, or any VirusTotal detection | suspicious |
| Otherwise | clean |

`CAPE_ALWAYS = True` sends every file to CAPE, even when VirusTotal has already decided. Set it to `False` to skip
detonation when 5 or more engines already flag the file.

Because the sandbox has no network, the malscore of samples that depend on their command server stays low. CAPE
still records the connection attempts, which show up as techniques such as T1071.

## Stage 4: Action

The email's overall verdict is the worst of the triage verdict and every file verdict. Suspicious or malicious
email is quarantined by `vault.py`:

1. **Vault.** The original email is copied to `~/analyzer/quarantine/emails/<case-id>.eml` (folder `chmod 700`, file
   read-only), and its hash is checked against the intake hash. Each case gets an ID like `Q-20261014-0002`.
2. **Purge.** The email is moved to Gmail's Trash and expunged, then the analyzer checks All Mail to confirm it's
   gone from the web, phone and desktop clients.
3. **Stub.** A plain-text `[QUARANTINED]` notice is put in the inbox in its place, with the sender, verdict,
   reasons and case ID, defanged and with no links or attachments.
4. **Files.** Downloaded and attached payloads are kept as `~/analyzer/quarantine/<sha256>.quarantined`.

It fails closed: if the vault copy can't be verified, nothing is deleted and the email stays in `Pending`. Every
step is appended to `~/analyzer/quarantine/custody.jsonl` with a timestamp, the Linux user and the hash.

| Command | What it does |
|---|---|
| `--list-quarantine` | Every case, its verdict and whether it's held or released |
| `--custody <case-id>` | The full chain of custody for one case, with a fresh hash check |
| `--release <case-id>` | False positive: checks the hash, puts the email back in the inbox with its original date, and removes the stub |
| `--release-file <sha256>` | Restores one quarantined file |

## Stage 5: Report

`ai_report.py` collects every log event for the email, adds the CAPE signature descriptions and network contacts,
and writes a report to `~/analyzer/reports/<case-id>.md`: a verdict and headline, a summary, a timeline,
indicators, ATT&CK techniques and recommendations.

What the AI receives: verdicts, scores, hashes, file names, VirusTotal counts, CAPE signature names, ATT&CK IDs,
and defanged URLs with the `#key` and query string removed. The email body, attachments and payload never leave
the VM. The AI doesn't decide anything; the verdict and the quarantine happen in Stages 2 to 4. When the Claude
Code backend is used, it runs with every tool turned off.

## Logging

Every stage appends JSON lines to `~/analyzer/logs/analyzer.json`:

| `event_type` | Written when |
|---|---|
| `email_triage` | An email gets its final verdict (with the triage findings) |
| `link_fetch` | A link is followed (`status`: downloaded, blocked, no file, ...) |
| `attachment_scan` | A file finishes YARA, VirusTotal and CAPE |
| `quarantine` | Each vault step (`action`: intake, quarantined, purged_from_gmail, stub_delivered, released, or `*_failed`) |
| `auth_failed` | The Gmail token can't be refreshed |

Example lines from the run against the red team's email (shortened where marked):

```json
{"timestamp": "2026-10-15T10:17:02-04:00", "event_type": "quarantine", "actor": "analyst", "action": "intake", "sha256": "575b310a...f71e6565", "message_id": "<...@proton.me>", "source": "gmail", "file": "email_1.eml"}
{"timestamp": "2026-10-15T10:17:19-04:00", "event_type": "link_fetch", "email_subject": "IMPORTANT ZOOM UPDATE", "url": "https://limewire.com/d/<id>#<key>", "final_url": "https://limewire.com/d/<id>#<key>", "status": "downloaded", "method": "browser", "filename": "link_Zoom_update.exe", "size_bytes": 701017}
{"timestamp": "2026-10-15T10:18:40-04:00", "event_type": "attachment_scan", "email_from": "RegiOnalWaterIT <Regi0nalWaterIT@proton.me>", "email_subject": "IMPORTANT ZOOM UPDATE", "filename": "link_Zoom_update.exe", "sha256": "b82603eda067f7579d91515c45f2a3c8c3343289621a41fa60a68d4eb1af72b8", "size_bytes": 701017, "yara_matches": [], "vt_found": true, "vt_malicious": 18, "vt_suspicious": 0, "cape_task_id": 29, "cape_malscore": 1.9, "cape_signatures": ["..."], "cape_high_severity": [], "cape_ttps": ["T1027", "T1036", "T1055", "T1071", "T1553"], "verdict": "malicious"}
{"timestamp": "2026-10-15T10:18:41-04:00", "event_type": "email_triage", "email_from": "RegiOnalWaterIT <Regi0nalWaterIT@proton.me>", "email_subject": "IMPORTANT ZOOM UPDATE", "spf": "pass", "dkim": "pass", "dmarc": "pass", "urls": ["https://limewire.com/d/<id>#<key>"], "attachment_sha256": [], "findings": ["file_sharing_link", "link_text_brand_mismatch", "urgency", "download_lure", "freemail_impersonation"], "triage_score": 11, "triage_verdict": "malicious", "attachment_verdicts": ["malicious"], "verdict": "malicious"}
{"timestamp": "2026-10-15T10:18:42-04:00", "event_type": "quarantine", "actor": "analyst", "action": "quarantined", "qid": "Q-20261015-0002", "sha256": "575b310a...f71e6565", "message_id": "<...@proton.me>", "email_from": "...", "email_subject": "IMPORTANT ZOOM UPDATE", "verdict": "malicious", "findings": ["..."]}
{"timestamp": "2026-10-15T10:18:44-04:00", "event_type": "quarantine", "actor": "analyst", "action": "purged_from_gmail", "qid": "Q-20261015-0002", "message_id": "<...@proton.me>", "folder": "Pending"}
{"timestamp": "2026-10-15T10:18:45-04:00", "event_type": "quarantine", "actor": "analyst", "action": "stub_delivered", "qid": "Q-20261015-0002", "stub_message_id": "<...@analyzer.local>"}
```

The field names match the code; timestamps, the key and some IDs are illustrative. Every line has
`timestamp` and `event_type`, so a single Wazuh JSON decoder handles them all.

A Wazuh agent ships these lines to the manager. [`wazuh/local_rules.example.xml`](../wazuh/local_rules.example.xml)
turns them into alerts, for example level 12 for a malicious email and for any failed quarantine step.

## Limits

- **Post-delivery, not inline.** Gmail delivers the email first and the analyzer removes it seconds later. Stopping
  it before delivery needs a mail gateway, for example Google Workspace inbound routing.
- **Links can expire.** One-time or expiring share links may be dead by the time they're checked. Links behind a
  login or CAPTCHA can't be fetched.
- **Fetching tells the sender.** Downloading the file shows the attacker's server that someone requested it.
  Commercial gateways fetch from a separate, disposable network.
- **Sandbox evasion.** Some malware detects VMs or waits before acting. The other layers (triage, VirusTotal,
  YARA) still apply.
