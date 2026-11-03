import os
import sys
import time
import json
import shutil
import hashlib
import argparse
import requests
from email import policy
from email.parser import BytesParser
from datetime import datetime, timezone
from imap_tools import MailBox, AND, H
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
import vault
import linkfetch
import ai_report
import display as ui

CAPE_URL = "http://localhost:8000/apiv2"
LOG_FILE = os.path.expanduser("~/analyzer/logs/analyzer.json")
QUARANTINE_DIR = os.path.expanduser("~/analyzer/quarantine")
RELEASED_DIR = os.path.expanduser("~/analyzer/released")

# Gmail labels show up over IMAP as folders.
PENDING_FOLDER = "Pending"        # held here while being analyzed
QUARANTINE_AT = "suspicious"      # lowest verdict that gets quarantined
YARA_DIR = os.path.expanduser("~/analyzer/yara")  # every .yar/.yara file in here is loaded
YARA_VERDICT = "suspicious"       # minimum verdict when any YARA rule matches
CAPE_ALWAYS = True                # detonate even when VirusTotal is already conclusive

# phish_triage.py lives one folder up (blue-team/); make it importable from here.
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))   # fallback only: a copy next to this script wins
from phish_triage import triage, print_report, SUSPICIOUS_AT, MALICIOUS_AT

VERDICT_RANK = {"clean": 0, "suspicious": 1, "malicious": 2}

GMAIL_SCOPES = ["https://mail.google.com/"]
TOKEN_FILE = os.path.expanduser("~/analyzer/oauth/token.json")


def get_access_token():
    creds = Credentials.from_authorized_user_file(TOKEN_FILE, GMAIL_SCOPES)
    if not creds.valid:
        try:
            creds.refresh(Request())
        except RefreshError as e:
            log_event({"event_type": "auth_failed", "reason": str(e),
                       "fix": "run oauth/auth_setup.py"})
            raise SystemExit(f"Gmail OAuth refresh failed: {e}. Run auth_setup.py again.")
        with open(TOKEN_FILE, "w") as f:
            f.write(creds.to_json())
    return creds.token


def gmail_connect(folder="INBOX"):
    """One place that logs in to Gmail. Everything else (and vault.py) calls this."""
    return MailBox('imap.gmail.com').xoauth2(os.environ["GMAIL_USER"], get_access_token(),
                                             initial_folder=folder)


def submit_to_cape(filepath, machine="win10"):
    url = f"{CAPE_URL}/tasks/create/file/"

    try:
        with open(filepath, "rb") as f:
            response = requests.post(
                url,
                files={"file": f},
                data={"machine": machine},
                timeout=60,
            )
    except requests.RequestException as e:
        print(f"Could not reach CAPE: {e}")
        return None

    if response.status_code != 200:
        print(f"CAPE returned HTTP {response.status_code}: {response.text}")
        return None

    result = response.json()

    if result.get("error"):
        print(f"CAPE rejected the file: {result.get('error_value') or result.get('errors')}")
        return None

    task_ids = result.get("data", {}).get("task_ids", [])
    if not task_ids:
        print(f"CAPE gave no task ID: {result}")
        return None

    return task_ids[0]


def wait_for_cape(task_id, timeout=600, interval=15, progress=lambda status: None):
    url = f"{CAPE_URL}/tasks/status/{task_id}/"
    start = time.time()

    while time.time() - start < timeout:
        try:
            response = requests.get(url, timeout=30)
            result = response.json()
        except (requests.RequestException, ValueError) as e:
            print(f"  Could not check CAPE status ({e}), retrying...")
            time.sleep(interval)
            continue

        if result.get("error"):
            print(f"  CAPE status error: {result}")
            return False

        status = result.get("data")
        print(f"  CAPE status: {status}")
        progress(f"{status}  {int(time.time() - start)} s")

        if status == "reported":
            return True
        if status in ("failed_analysis", "failed_processing", "failed_reporting"):
            print(f"  CAPE analysis failed: {status}")
            return False

        time.sleep(interval)

    print(f"  Gave up waiting for CAPE task {task_id} after {timeout} seconds")
    return False


def get_cape_verdict(task_id):
    url = f"{CAPE_URL}/tasks/get/report/{task_id}/"

    try:
        response = requests.get(url, timeout=120)
        report = response.json()
    except (requests.RequestException, ValueError) as e:
        print(f"  Could not fetch CAPE report: {e}")
        return None

    signatures = report.get("signatures", [])

    ttps = []
    for item in report.get("ttps", []):
        if isinstance(item, dict):
            ttps.extend(item.get("ttps", []) or [item.get("ttp")])
        else:
            ttps.append(item)

    return {
        "task_id": task_id,
        "malscore": round(report.get("malscore", 0), 1),
        "malstatus": report.get("malstatus"),
        "signatures": [s.get("name") for s in signatures],
        "high_severity": [s.get("name") for s in signatures if s.get("severity", 0) >= 3],
        "ttps": sorted(set(t for t in ttps if t)),
    }


def decide_verdict(vt_stats, cape):
    vt_malicious = vt_stats["malicious"] if vt_stats else 0

    if vt_malicious >= 5:
        return "malicious"
    if cape:
        if cape["malscore"] >= 8 or len(cape["high_severity"]) >= 2:
            return "malicious"
        if cape["malscore"] >= 5 or cape["high_severity"] or vt_malicious > 0:
            return "suspicious"
    elif vt_malicious > 0:
        return "suspicious"
    return "clean"


def log_event(event):
    record = {"timestamp": datetime.now(timezone.utc).astimezone().isoformat(), **event}
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")


def fetch_new_emails(save_dir="emails"):
    """Save every unread email as a .eml file (evidence copy) and return the paths.

    Emails without attachments are kept too: a link-only phish has nothing for
    VirusTotal/CAPE to scan, but the header and link triage still catches it.
    """
    os.makedirs(save_dir, exist_ok=True)
    saved_emails = []

    with gmail_connect() as mailbox:
        if not mailbox.folder.exists(PENDING_FOLDER):
            mailbox.folder.create(PENDING_FOLDER)

        for msg in mailbox.fetch(AND(seen=False)):
            print(f"New email from: {msg.from_}, subject: {msg.subject}")
            filepath = os.path.join(save_dir, f"{msg.uid or int(time.time())}.eml")
            with open(filepath, "wb") as f:
                f.write(msg.obj.as_bytes())
            saved_emails.append(filepath)
            vault.record_intake(filepath, (msg.obj["Message-ID"] or "").strip())

            # Hold it out of the inbox until we have a verdict. If the script
            # crashes mid-analysis the email stays held (fail closed).
            mailbox.move(msg.uid, PENDING_FOLDER)
            print(f"  Moved to {PENDING_FOLDER} while analyzing")

    return saved_emails


def move_email(message_id, from_folder, to_folder):
    """Move one email between Gmail labels, found by its Message-ID header.

    UIDs change when Gmail moves a message, so Message-ID is the stable way
    to find it again after a long CAPE run. Opens its own short connection.
    """
    with gmail_connect(from_folder) as mailbox:
        uids = mailbox.uids(AND(header=H("Message-ID", message_id)))
        if not uids:
            print(f"  Could not find {message_id} in {from_folder}")
            return False
        mailbox.move(uids, to_folder)
    return True


def release_email(message_id, from_folder=PENDING_FOLDER):
    if move_email(message_id, from_folder, "INBOX"):
        print("Released: email moved back to the inbox")
        return True
    return False


def quarantine_file(filepath, sha256, email_from, email_subject, verdict):
    """Lock an attachment away so nobody opens it by accident.

    Renamed to <sha256>.quarantined (no clickable extension), made read-only,
    and recorded in a manifest so it can be released later.
    """
    os.makedirs(QUARANTINE_DIR, mode=0o700, exist_ok=True)
    os.chmod(QUARANTINE_DIR, 0o700)
    dest = os.path.join(QUARANTINE_DIR, f"{sha256}.quarantined")

    if os.path.exists(dest):
        os.remove(filepath)  # same file already quarantined
    else:
        shutil.move(filepath, dest)
        os.chmod(dest, 0o400)

    entry = {
        "timestamp": datetime.now(timezone.utc).astimezone().isoformat(),
        "sha256": sha256,
        "original_filename": os.path.basename(filepath),
        "email_from": email_from,
        "email_subject": email_subject,
        "verdict": verdict,
    }
    with open(os.path.join(QUARANTINE_DIR, "manifest.jsonl"), "a") as f:
        f.write(json.dumps(entry) + "\n")

    print(f"QUARANTINED: {entry['original_filename']} -> {dest}")
    return dest


def release_file(sha256):
    """Restore a quarantined attachment (false positive) to the released folder."""
    src = os.path.join(QUARANTINE_DIR, f"{sha256}.quarantined")
    if not os.path.exists(src):
        raise SystemExit(f"No quarantined file with SHA-256 {sha256}")

    original = "unnamed"
    with open(os.path.join(QUARANTINE_DIR, "manifest.jsonl")) as f:
        for line in f:
            entry = json.loads(line)
            if entry["sha256"] == sha256:
                original = entry["original_filename"]

    os.makedirs(RELEASED_DIR, exist_ok=True)
    dest = os.path.join(RELEASED_DIR, original)
    os.chmod(src, 0o600)
    shutil.move(src, dest)
    print(f"Released: {sha256} -> {dest}")
    log_event({"event_type": "quarantine", "action": "file_released",
               "sha256": sha256, "filename": original})


def extract_attachments(eml_path, save_dir="attachments"):
    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    os.makedirs(save_dir, exist_ok=True)
    saved_files = []

    for part in msg.iter_attachments():
        safe_name = os.path.basename(part.get_filename() or "unnamed")
        filepath = os.path.join(save_dir, safe_name)
        with open(filepath, "wb") as f:
            f.write(part.get_payload(decode=True) or b"")
        print(f"  Saved attachment: {safe_name}")
        saved_files.append({
            "path": filepath,
            "email_from": str(msg.get("From", "")),
            "email_subject": str(msg.get("Subject", "")),
        })

    return saved_files


def email_recipient(eml_path):
    """The To: header of a saved email, for the Email Access display."""
    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f, headersonly=True)
    return str(msg.get("To", "")).strip()


def compute_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def check_virustotal(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    response = requests.get(url, headers=headers)

    if response.status_code == 404:
        return None
    elif response.status_code != 200:
        print(f"Unexpected error: {response.status_code} - {response.text}")
        return None

    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return stats


def get_file_metadata(filepath):
    size = os.path.getsize(filepath)
    return {
        "filename": os.path.basename(filepath),
        "size_bytes": size
    }


_yara_rules = None


def load_yara_rules():
    """Compile every rule file in YARA_DIR once. A broken file is skipped, not fatal."""
    global _yara_rules
    if _yara_rules is not None:
        return _yara_rules
    _yara_rules = []
    try:
        import yara
    except ImportError:
        print("YARA: yara-python not installed, skipping (pip install yara-python)")
        return _yara_rules
    if not os.path.isdir(YARA_DIR):
        print(f"YARA: no rules folder at {YARA_DIR}, skipping")
        return _yara_rules

    # Some public rule sets expect these variables to exist; empty values are fine.
    externals = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}
    for name in sorted(os.listdir(YARA_DIR)):
        if not name.endswith((".yar", ".yara")):
            continue
        try:
            _yara_rules.append(yara.compile(filepath=os.path.join(YARA_DIR, name), externals=externals))
        except yara.Error as e:
            print(f"YARA: skipped {name} ({e})")
    print(f"YARA: loaded {len(_yara_rules)} rule file(s) from {YARA_DIR}")
    return _yara_rules


def scan_yara(filepath):
    """Return the names of the YARA rules that match this file."""
    name = os.path.basename(filepath)
    externals = {"filename": name, "filepath": filepath,
                 "extension": os.path.splitext(name)[1].lower(), "filetype": "", "owner": ""}
    hits = []
    for rules in load_yara_rules():
        hits += [m.rule for m in rules.match(filepath, externals=externals, timeout=60)]
    return sorted(set(hits))


def static_scan(item, api_key):
    """Stage 2 for one file: hash, YARA, VirusTotal. Nothing is run."""
    filepath = item["path"]
    print(f"\n--- Analyzing {filepath} ---")
    file_hash = compute_hash(filepath)
    item["sha256"] = file_hash
    metadata = get_file_metadata(filepath)
    print(f"Filename: {metadata['filename']}  Size: {metadata['size_bytes']} bytes  SHA-256: {file_hash}")

    yara_hits = scan_yara(filepath)
    print(f"YARA: {', '.join(yara_hits) if yara_hits else 'no matches'}")

    stats = check_virustotal(file_hash, api_key)
    if stats is None:
        print("VirusTotal: hash not found — file may be unknown/new.")
    else:
        print(f"VirusTotal: {stats['malicious']} malicious, {stats['suspicious']} suspicious")
    return {"item": item, "sha256": file_hash, "metadata": metadata, "yara": yara_hits, "vt": stats}


def dynamic_scan(scan, progress=lambda status: None):
    """Stage 3 for one file: detonate in CAPE (unless VT is conclusive and CAPE_ALWAYS is off)."""
    stats, cape = scan["vt"], None
    if not CAPE_ALWAYS and stats and stats["malicious"] >= 5:
        print("CAPE: skipped (VirusTotal already conclusive)")
        scan["cape_skipped"] = True
    else:
        task_id = submit_to_cape(scan["item"]["path"])
        if task_id:
            print(f"CAPE: submitted as task {task_id}")
            progress(f"task {task_id} submitted")
            if wait_for_cape(task_id, progress=lambda s: progress(f"task {task_id}  {s}")):
                cape = get_cape_verdict(task_id)
        if cape:
            print(f"CAPE: malscore {cape['malscore']}, {len(cape['signatures'])} signatures, "
                  f"high severity: {cape['high_severity'] or 'none'}, ATT&CK: {', '.join(cape['ttps']) or 'none'}")
        else:
            print("CAPE: no result (submission failed, rejected, or timed out)")
    scan["cape"] = cape

    verdict = decide_verdict(stats, cape)
    if scan["yara"]:
        verdict = max(verdict, YARA_VERDICT, key=VERDICT_RANK.get)
    print(f"VERDICT: {verdict.upper()}")
    scan["verdict"] = verdict

    item, metadata = scan["item"], scan["metadata"]
    log_event({
        "event_type": "attachment_scan",
        "email_from": item["email_from"],
        "email_subject": item["email_subject"],
        "filename": metadata["filename"],
        "sha256": scan["sha256"],
        "source_url": item.get("source_url"),
        "size_bytes": metadata["size_bytes"],
        "yara_matches": scan["yara"],
        "vt_found": stats is not None,
        "vt_malicious": stats["malicious"] if stats else 0,
        "vt_suspicious": stats["suspicious"] if stats else 0,
        "cape_task_id": cape["task_id"] if cape else None,
        "cape_malscore": cape["malscore"] if cape else None,
        "cape_signatures": cape["signatures"] if cape else [],
        "cape_high_severity": cape["high_severity"] if cape else [],
        "cape_ttps": cape["ttps"] if cape else [],
        "verdict": verdict,
    })
    return verdict


def analyze_email(eml_path, api_key, held_in_gmail=False, n=1, total=1):
    with ui.quiet():
        print(f"\n=== Analyzing email {eml_path} ===")

    # ---- Stage 2: Static Analysis (the email, its links, and any file, without running anything)
    t0 = time.monotonic()
    with ui.working("Static analysis") as status, ui.quiet():
        status("reading headers, sender and links")
        triage_report, sections = triage(eml_path)
        print_report(triage_report, sections)
        attachments = extract_attachments(eml_path)
        if triage_report["urls"]:
            status("opening links in the isolated browser")
        attachments += linkfetch.fetch_link_payloads(triage_report, log_event)
        scans = []
        for item in attachments:
            status(f"hashing and looking up {os.path.basename(item['path'])}")
            scans.append(static_scan(item, api_key))
    triage_verdict = triage_report["verdict"].lower()
    static_verdict = max([triage_verdict] + [("malicious" if s["vt"] and s["vt"]["malicious"] >= 5 else
                                              "suspicious" if (s["vt"] and s["vt"]["malicious"]) or s["yara"] else "clean")
                                             for s in scans], key=VERDICT_RANK.get)

    if total > 1 or n > 1:
        ui.email_meta(triage_report["subject"], triage_report["sender"].get("from"), n, total,
                      recipient=email_recipient(eml_path))
    ui.stage(2, static_verdict.upper(), time.monotonic() - t0)
    ui.triage_block(triage_report, SUSPICIOUS_AT, MALICIOUS_AT)
    for s in scans:
        ui.file_lines(s["item"], s["metadata"]["size_bytes"], s["sha256"])
        ui.yara_line(s["yara"], bool(_yara_rules))
        ui.vt_line(s["vt"])
    if not scans:
        ui.no_files_line()

    # ---- Stage 3: Dynamic Analysis (detonate each file in the offline CAPE sandbox)
    t0 = time.monotonic()
    attachment_verdicts = []
    for s in scans:
        with ui.working(f"Detonating {s['metadata']['filename']} in the CAPE sandbox") as status, ui.quiet():
            attachment_verdicts.append(dynamic_scan(s, progress=status))
    if not scans:
        ui.stage(3, "NO FILE")
        ui.say("   ", ("Nothing to detonate", ui.MUTED))
    else:
        worst = max(attachment_verdicts, key=VERDICT_RANK.get)
        ran = [s for s in scans if not s.get("cape_skipped")]
        ui.stage(3, worst.upper() if ran else "SKIPPED", time.monotonic() - t0)
        for s in scans:
            if s.get("cape_skipped"):
                ui.say("   ", ("Skipped ", ui.MUTED), (s["metadata"]["filename"], "bold"), ("  VirusTotal was already conclusive", ui.DIM))
            else:
                ui.cape_block(s["cape"], s["metadata"]["filename"])

    # Overall verdict is the worst of the email triage and any file
    overall = max([triage_verdict] + attachment_verdicts, key=VERDICT_RANK.get)
    with ui.quiet():
        print(f"\nOVERALL EMAIL VERDICT: {overall.upper()} "
              f"(email triage: {triage_verdict}, attachments: {attachment_verdicts or 'none'})")

    log_event({
        "event_type": "email_triage",
        "email_from": triage_report["sender"]["from"],
        "email_subject": triage_report["subject"],
        "spf": triage_report["auth"]["spf"],
        "dkim": triage_report["auth"]["dkim"],
        "dmarc": triage_report["auth"]["dmarc"],
        "urls": [u["url"] for u in triage_report["urls"]],
        "attachment_sha256": [a["sha256"] for a in triage_report["attachments"]],
        "findings": [f["check"] for f in triage_report["findings"]],
        "triage_score": triage_report["score"],
        "triage_verdict": triage_verdict,
        "attachment_verdicts": attachment_verdicts,
        "verdict": overall,
    })

    # ---- Stage 4: Action (quarantine or release)
    t0 = time.monotonic()
    message_id = triage_report["message_id"]
    qid = None
    quarantining = VERDICT_RANK[overall] >= VERDICT_RANK[QUARANTINE_AT]
    with ui.working("Quarantining" if quarantining else "Releasing"), ui.quiet():
        if quarantining:
            for item in attachments:
                quarantine_file(item["path"], item["sha256"], item["email_from"],
                                item["email_subject"], overall)
            # Vault the email, delete it from Gmail, leave a warning stub.
            # If anything fails it stays in Pending, never back in the inbox.
            qid = vault.quarantine(eml_path, triage_report, overall,
                                   held_folder=PENDING_FOLDER if held_in_gmail else None)
            done = {r["action"] for r in vault.custody_records(qid)} if qid else set()
        elif held_in_gmail:
            released = release_email(message_id)
    ui.stage(4, "DONE", time.monotonic() - t0)
    if quarantining:
        if attachments:
            ui.check(f"{len(attachments)} file(s) quarantined", "read-only, renamed, no clickable extension")
        ui.check("Email moved to the vault", qid or "FAILED", ok=bool(qid), extra_style="bold")
        if held_in_gmail:
            ui.check("Deleted from the Gmail inbox", ok="purged_from_gmail" in done,
                     extra="" if "purged_from_gmail" in done else "still held in Pending")
            ui.check("User warned", "[QUARANTINED] notice left in its place" if "stub_delivered" in done else "stub not delivered",
                     ok="stub_delivered" in done)
        else:
            ui.check("Local file analyzed", "no Gmail changes in --eml mode")
    elif held_in_gmail:
        ui.check("Delivered back to the inbox", ok=bool(released))
    else:
        ui.check("No action needed")
    ui.check("Events sent to Wazuh", os.path.basename(LOG_FILE))

    # ---- Stage 5: Report
    t0 = time.monotonic()
    if quarantining:
        path, headline, summary, by = None, f'"{triage_report["subject"]}"', "", None
        with ui.working("Writing the incident report"), ui.quiet():
            try:
                path, headline, summary, by = ai_report.run(subject=triage_report["subject"])
            except Exception as e:      # the report must never break the pipeline
                print(f"Report failed: {e}")
                summary = f"Report could not be written ({e}). The analysis log has every detail."
        ui.stage(5, "DONE", time.monotonic() - t0)
        ui.report_panel(overall, headline, summary, path, by)
    else:
        ui.stage(5, "DONE", time.monotonic() - t0)
        ui.report_panel(overall, f'"{triage_report["subject"]}"',
                        f"No sign of phishing (risk score {triage_report['score']}). "
                        + ("The email was delivered to the inbox." if held_in_gmail else ""))


def main():
    parser = argparse.ArgumentParser(description="Phishing email analyzer")
    parser.add_argument("--eml", help="analyze a local .eml file instead of fetching from Gmail (offline test)")
    parser.add_argument("--release", metavar="CASE_ID", help="false positive: put a vaulted email back in the inbox (e.g. Q-20261008-0001)")
    parser.add_argument("--release-file", metavar="SHA256", help="restore a quarantined attachment")
    parser.add_argument("--list-quarantine", action="store_true", help="show every vaulted email and its status")
    parser.add_argument("--custody", metavar="CASE_ID", help="show the chain of custody for one case and re-check its hash")
    parser.add_argument("--plain", action="store_true", help="old line-by-line output instead of the stage view (debugging)")
    args = parser.parse_args()
    ui.set_plain(args.plain)

    vault.setup(connect=gmail_connect, log_event=log_event)

    if args.list_quarantine:
        vault.list_vault()
        return
    if args.custody:
        vault.show_custody(args.custody)
        return
    if args.release:
        vault.release(args.release)
        return
    if args.release_file:
        release_file(args.release_file)
        return

    API_KEY = os.environ.get("VT_API_KEY")
    if not API_KEY:
        raise SystemExit("VT_API_KEY environment variable not set.")

    # ---- Stage 1: Email Access
    ui.header()
    t0 = time.monotonic()
    with ui.working("Signing in to Gmail" if not args.eml else "Loading the saved email"), ui.quiet():
        if args.eml:
            eml_paths = [args.eml]
            vault.record_intake(args.eml, triage(args.eml, use_vt=False)[0]["message_id"], source="local_file")
        else:
            eml_paths = fetch_new_emails()
    ui.stage(1, "DONE", time.monotonic() - t0)
    if args.eml:
        ui.check("Loaded a saved email", os.path.basename(args.eml) + "  (offline, Gmail untouched)")
    else:
        ui.check("Signed in to Gmail", "OAuth 2.0, no password stored")
        ui.check(f"{len(eml_paths)} new email(s)" + (", held in Pending while analyzed" if eml_paths else ""))
    for p in eml_paths:
        ui.check("Evidence copy saved", f"sha256 {vault.sha256_of(p)[:8]}…{vault.sha256_of(p)[-8:]}")
    if len(eml_paths) == 1:
        r = triage(eml_paths[0], use_vt=False)[0]
        ui.email_meta(r["subject"], r["sender"].get("from"), recipient=email_recipient(eml_paths[0]))

    if not eml_paths:
        ui.say("   ", ("Inbox is clear. Nothing to analyze.", ui.MUTED))
        if args.plain:
            print("No new emails found.")
        return

    for i, eml_path in enumerate(eml_paths, 1):
        analyze_email(eml_path, API_KEY, held_in_gmail=not args.eml, n=i, total=len(eml_paths))

if __name__ == "__main__":
    main()
