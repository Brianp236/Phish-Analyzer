"""Quarantine vault: the analyzer VM holds the only copy of a quarantined email.

Flow for a suspicious/malicious email:
  1. vault_email()     copy the .eml into the vault (read-only), verify its hash
  2. purge()           delete the original from Gmail for good (Trash + expunge)
  3. deliver_stub()    put a plain-text warning in the inbox in its place
Release (false positive, analyst only):
  4. release()         put the original back with its original date, remove the stub

Every step is written to custody.jsonl (append-only): who, when, which hash.
Fails closed: if the vault copy can't be verified, nothing is deleted from Gmail.

The analyzer wires this up once at startup:
    vault.setup(connect=gmail_connect, log_event=log_event)
"""
import os
import re
import json
import shutil
import getpass
import hashlib
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import make_msgid, parsedate_to_datetime
from imap_tools import AND, H

VAULT_DIR = os.path.expanduser("~/analyzer/quarantine/emails")
RELEASED_DIR = os.path.expanduser("~/analyzer/released/emails")
CUSTODY_LOG = os.path.expanduser("~/analyzer/quarantine/custody.jsonl")

_connect = None      # function(folder) -> logged-in MailBox, set by setup()
_log_event = None    # analyzer's log_event, so vault actions also reach Wazuh
_intake = {}         # eml path -> sha256 recorded at intake


def setup(connect, log_event):
    global _connect, _log_event
    _connect, _log_event = connect, log_event


# ---------- chain of custody ----------

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def custody(action, **fields):
    """Append one line to the custody log and send the same event to Wazuh."""
    record = {
        "timestamp": datetime.now(timezone.utc).astimezone().isoformat(),
        "actor": getpass.getuser(),
        "action": action,
        **fields,
    }
    os.makedirs(os.path.dirname(CUSTODY_LOG), mode=0o700, exist_ok=True)
    with open(CUSTODY_LOG, "a") as f:
        f.write(json.dumps(record) + "\n")
    os.chmod(CUSTODY_LOG, 0o600)
    if _log_event:
        _log_event({"event_type": "quarantine", **record})
    return record


def custody_records(qid=None):
    if not os.path.exists(CUSTODY_LOG):
        return []
    with open(CUSTODY_LOG) as f:
        records = [json.loads(line) for line in f if line.strip()]
    return [r for r in records if qid is None or r.get("qid") == qid]


def record_intake(eml_path, message_id, source="gmail"):
    """Hash the email the moment it is saved. Everything later is checked against this."""
    digest = sha256_of(eml_path)
    _intake[os.path.abspath(eml_path)] = digest
    custody("intake", sha256=digest, message_id=message_id, source=source,
            file=os.path.basename(eml_path))
    return digest


def new_quarantine_id():
    """Q-YYYYMMDD-NNNN, numbered per day."""
    today = datetime.now().strftime("%Y%m%d")
    prefix = f"Q-{today}-"
    taken = [r["qid"] for r in custody_records() if r.get("qid", "").startswith(prefix)]
    return f"{prefix}{len(set(taken)) + 1:04d}"


def _read_eml(path):
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


# ---------- 1. vault ----------

def vault_email(eml_path, report, verdict):
    """Copy the email into the vault and prove the copy is intact.

    Returns the quarantine ID, or None if the copy could not be verified
    (in which case the caller must NOT delete anything from Gmail).
    """
    os.makedirs(VAULT_DIR, mode=0o700, exist_ok=True)
    os.chmod(VAULT_DIR, 0o700)

    expected = _intake.get(os.path.abspath(eml_path)) or sha256_of(eml_path)
    qid = new_quarantine_id()
    dest = os.path.join(VAULT_DIR, f"{qid}.eml")
    shutil.copy2(eml_path, dest)
    os.chmod(dest, 0o400)

    actual = sha256_of(dest)
    if actual != expected:
        custody("vault_failed", qid=qid, expected_sha256=expected, sha256=actual,
                message_id=report["message_id"])
        print(f"VAULT ERROR: copy hash does not match intake hash, leaving email held")
        return None

    custody("quarantined", qid=qid, sha256=actual, message_id=report["message_id"],
            email_from=report["sender"]["from"], email_subject=report["subject"],
            verdict=verdict, findings=[f["check"] for f in report["findings"]])
    print(f"VAULTED: {qid} -> {dest} (sha256 verified)")
    return qid


# ---------- 2. purge from Gmail ----------

def _special_folder(mailbox, flag, fallback):
    """Gmail's system folders are localized ([Gmail]/Trash vs [Gmail]/Bin), so find them by flag."""
    for f in mailbox.folder.list():
        if flag in f.flags:
            return f.name
    return fallback


def purge(message_id, folder):
    """Delete every copy of message_id in `folder` from Gmail for good.

    Moving to Trash and expunging there is Gmail's permanent delete.
    Afterwards All Mail is searched to prove it is gone.
    """
    with _connect(folder) as mailbox:
        trash = _special_folder(mailbox, "\\Trash", "[Gmail]/Trash")
        all_mail = _special_folder(mailbox, "\\All", "[Gmail]/All Mail")

        uids = mailbox.uids(AND(header=H("Message-ID", message_id)))
        if not uids:
            print(f"  Purge: {message_id} not found in {folder}")
            return False
        mailbox.move(uids, trash)

        mailbox.folder.set(trash)
        trash_uids = mailbox.uids(AND(header=H("Message-ID", message_id)))
        if trash_uids:
            mailbox.delete(trash_uids)

        mailbox.folder.set(all_mail)
        leftover = mailbox.uids(AND(header=H("Message-ID", message_id)))
    return not leftover


# ---------- 3. warning stub ----------

_HOSTLIKE = re.compile(r"(?:https?://)?[\w-]+(?:\.[\w-]+)+\S*")


def _defang(text):
    """Stop Gmail turning domains/URLs in the stub into clickable links."""
    return _HOSTLIKE.sub(lambda m: m.group(0).replace("http", "hxxp", 1).replace(".", "[.]"),
                         text).replace("@", "[@]")


def build_stub(report, qid, verdict):
    stub = EmailMessage()
    stub["From"] = "Security Quarantine <quarantine@analyzer.local>"
    stub["To"] = report.get("to") or os.environ.get("GMAIL_USER", "")
    stub["Subject"] = f"[QUARANTINED] {report['subject']}"
    stub["Message-ID"] = make_msgid(idstring=qid, domain="quarantine.local")
    stub["X-Quarantine-Id"] = qid
    stub["Date"] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")

    reasons = "\n".join(f"  - {_defang(f['detail'])}" for f in report["findings"]) or "  - see analyst"
    stub.set_content(
        f"An email addressed to you was quarantined by the security team.\n\n"
        f"  From:     {_defang(report['sender']['from'])}\n"
        f"  Subject:  {_defang(report['subject'])}\n"
        f"  Verdict:  {verdict.upper()}\n"
        f"  Case ID:  {qid}\n\n"
        f"Why it was flagged:\n{reasons}\n\n"
        f"The original has been removed from your mailbox. Nothing in it can be opened from here.\n"
        f"If you were expecting this email, contact the security team and quote case {qid}.\n"
    )
    return stub


def deliver_stub(report, qid, verdict):
    stub = build_stub(report, qid, verdict)
    with _connect("INBOX") as mailbox:
        mailbox.append(stub.as_bytes(), "INBOX")
    custody("stub_delivered", qid=qid, stub_message_id=stub["Message-ID"])
    return stub["Message-ID"]


# ---------- the whole quarantine, in order ----------

def quarantine(eml_path, report, verdict, held_folder=None):
    """Vault -> purge -> stub. held_folder=None means offline (--eml): vault only."""
    qid = vault_email(eml_path, report, verdict)
    if not qid:
        return None
    if held_folder is None:
        return qid

    message_id = report["message_id"]
    try:
        purged = purge(message_id, held_folder)
        error = None if purged else "still found in All Mail after delete"
    except Exception as e:  # network drop, IMAP error: don't crash the whole run
        purged, error = False, str(e)
    if not purged:
        custody("purge_failed", qid=qid, message_id=message_id, folder=held_folder, error=error)
        print(f"PURGE ERROR ({error}): original is still held in {held_folder}, check by hand")
        return qid
    custody("purged_from_gmail", qid=qid, message_id=message_id, folder=held_folder)
    print(f"PURGED: original deleted from Gmail")

    try:
        deliver_stub(report, qid, verdict)
        print(f"STUB: warning delivered to the inbox (case {qid})")
    except Exception as e:  # original is already safe in the vault, so just record it
        custody("stub_failed", qid=qid, error=str(e))
        print(f"STUB ERROR ({e}): email is vaulted but the user got no warning")
    return qid


# ---------- 4. release (false positive) ----------

def release(qid):
    records = custody_records(qid)
    if any(r["action"] == "released" for r in records):
        raise SystemExit(f"{qid} was already released")
    entry = next((r for r in records if r["action"] == "quarantined"), None)
    src = os.path.join(VAULT_DIR, f"{qid}.eml")
    if not entry or not os.path.exists(src):
        raise SystemExit(f"No quarantined email {qid}")

    if sha256_of(src) != entry["sha256"]:
        custody("integrity_failed", qid=qid, expected_sha256=entry["sha256"])
        raise SystemExit(f"{qid}: vault copy hash changed since quarantine, not releasing")

    with open(src, "rb") as f:
        raw = f.read()
    try:
        original_date = parsedate_to_datetime(_read_eml(src)["Date"])
    except (TypeError, ValueError):
        original_date = None

    with _connect("INBOX") as mailbox:
        mailbox.append(raw, "INBOX", dt=original_date)

    stub = next((r for r in records if r["action"] == "stub_delivered"), None)
    if stub:
        with _connect("INBOX") as mailbox:
            all_mail = _special_folder(mailbox, "\\All", "[Gmail]/All Mail")
        purge(stub["stub_message_id"], all_mail)

    os.makedirs(RELEASED_DIR, mode=0o700, exist_ok=True)
    os.chmod(src, 0o600)
    shutil.move(src, os.path.join(RELEASED_DIR, f"{qid}.eml"))
    custody("released", qid=qid, sha256=entry["sha256"], message_id=entry["message_id"])
    print(f"Released {qid}: original back in the inbox, warning stub removed")


# ---------- analyst views ----------

def list_vault():
    by_qid = {}
    for r in custody_records():
        if r.get("qid"):
            by_qid.setdefault(r["qid"], []).append(r)
    if not by_qid:
        print("Vault is empty.")
        return
    print(f"{'CASE':<16} {'STATUS':<10} {'VERDICT':<11} {'FROM':<30} SUBJECT")
    for qid, rs in sorted(by_qid.items()):
        q = next((r for r in rs if r["action"] == "quarantined"), None)
        if not q:
            continue
        status = "released" if any(r["action"] == "released" for r in rs) else "held"
        print(f"{qid:<16} {status:<10} {q['verdict']:<11} {q['email_from'][:30]:<30} {q['email_subject'][:40]}")


def show_custody(qid):
    records = custody_records(qid)
    if not records:
        raise SystemExit(f"No custody records for {qid}")
    q = next((r for r in records if r["action"] == "quarantined"), {})
    intake = [r for r in custody_records() if r["action"] == "intake"
              and r.get("message_id") == q.get("message_id")]
    for r in intake[-1:] + records:
        print(f"{r['timestamp']}  {r['actor']:<14} {r['action']:<18} {r.get('sha256', '')[:16]}")
    src = os.path.join(VAULT_DIR, f"{qid}.eml")
    if os.path.exists(src) and q:
        ok = sha256_of(src) == q["sha256"]
        print(f"\nVault copy integrity: {'OK, hash matches quarantine record' if ok else 'MISMATCH'}")
