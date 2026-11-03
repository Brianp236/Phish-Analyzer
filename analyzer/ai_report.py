"""AI incident report for one analyzed email: the REPORT stage.

Reads the analyzer's JSON log, gathers every event for one email, adds the
signature descriptions and network contacts from CAPE, and asks Claude to write
a short incident report an analyst (or a manager) can read in a minute.

What leaves the VM: verdicts, scores, hashes, file names, CAPE signature names,
ATT&CK IDs and defanged URLs with the #key and ?query removed. The email body,
the attachments and the payload itself are never sent.

    export ANTHROPIC_API_KEY=...                  # Claude (paid, best writing), or:
    export AI_BACKEND=ollama                      # free: a local model via Ollama, nothing leaves the VM
    export AI_BACKEND=claude-code                 # uses your Claude Pro/Max plan via the `claude` CLI (log in once)
    (with neither, a template report is written)
    python3 ai_report.py                          # latest email in the log
    python3 ai_report.py --subject "IMPORTANT ZOOM UPDATE"
    python3 ai_report.py --no-ai                  # template only, no API call

new_analyzer.py calls run() at the end of analyze_email(), so a report is
written for every email that gets quarantined.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timedelta
from urllib.parse import urlsplit

import requests

LOG_FILE = os.path.expanduser("~/analyzer/logs/analyzer.json")
REPORT_DIR = os.path.expanduser("~/analyzer/reports")
CAPE_URL = "http://localhost:8000/apiv2"
API_URL = "https://api.anthropic.com/v1/messages"
MODEL = os.environ.get("AI_REPORT_MODEL", "claude-sonnet-5-5")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:3b")

ATTACK_NAMES = {
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1055": ("Process Injection", "Privilege Escalation"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1553": ("Subvert Trust Controls", "Defense Evasion"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1112": ("Modify Registry", "Defense Evasion"),
    "T1547": ("Boot or Logon Autostart Execution", "Persistence"),
    "T1566": ("Phishing", "Initial Access"),
    "T1204": ("User Execution", "Execution"),
}

SYSTEM_PROMPT = """You are a SOC analyst writing an incident report about one phishing email that an automated
pipeline caught. Write for two readers: a manager who reads only the first paragraph, and an analyst who reads all of it.

Rules:
- Use only the facts in the JSON you are given. If something is not in the facts, say it is unknown. Never invent a
  malware family, threat actor, IP address or domain.
- The sandbox guest had no network access, so network behaviour means attempts, not successful connections.
- Keep URLs exactly as given (they are defanged on purpose).
- Plain, professional English. No hype, no emoji.

Output Markdown in exactly this shape:
# <one-line headline, under 70 characters>
## Summary
<2-3 sentences: what the email was, what the payload does, what was done about it>
## What happened
<numbered timeline, one line per stage: email access, static analysis, dynamic analysis, action>
## Why it was flagged
<bullets: the triage findings and detection results that mattered most>
## Sandbox behaviour
<table: ATT&CK ID | Technique | What it means here>
## Indicators of compromise
<table: Type | Value>
## Actions taken
<bullets>
## Recommendations
<3-5 bullets, specific to this incident>
"""


# ---------------- gather the facts ----------------

def defang(url):
    """hxxps://host[.]com/path, with the #key and ?query dropped."""
    if not url:
        return url
    p = urlsplit(url)
    host = (p.hostname or "").replace(".", "[.]")
    return f"{p.scheme.replace('http', 'hxxp')}://{host}{p.path}" + ("  (key removed)" if p.fragment else "")


def load_events(log_file=LOG_FILE):
    events = []
    with open(log_file) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass
    return events


def _ts(e):
    return datetime.fromisoformat(e["timestamp"])


def gather_case(events, subject=None):
    """Every log event for the latest email (optionally the latest with this subject)."""
    triages = [e for e in events if e.get("event_type") == "email_triage"
               and (subject is None or e.get("email_subject") == subject)]
    if not triages:
        raise SystemExit(f"No analyzed email found in the log{' with subject ' + repr(subject) if subject else ''}.")
    triage = triages[-1]
    end = _ts(triage)
    # This email's run starts after the previous email's triage event.
    earlier = [_ts(e) for e in events if e.get("event_type") == "email_triage" and _ts(e) < end]
    start = max(earlier) if earlier else end - timedelta(hours=1)
    later = [_ts(e) for e in events if e.get("event_type") == "email_triage" and _ts(e) > end]
    stop = min(later) if later else end + timedelta(minutes=10)

    same = lambda e: e.get("email_subject") == triage["email_subject"]
    in_run = lambda e: start < _ts(e) <= end
    return {
        "triage": triage,
        "links": [e for e in events if e.get("event_type") == "link_fetch" and same(e) and in_run(e)],
        "scans": [e for e in events if e.get("event_type") == "attachment_scan" and same(e) and in_run(e)],
        "quarantine": [e for e in events if e.get("event_type") == "quarantine" and end <= _ts(e) < stop],
    }


def cape_details(task_id, cape_url=CAPE_URL):
    """Signature descriptions and network contacts from the local CAPE report. Empty if CAPE is unreachable."""
    try:
        report = requests.get(f"{cape_url}/tasks/get/report/{task_id}/", timeout=60).json()
    except (requests.RequestException, ValueError):
        return {}
    net = report.get("network") or {}
    return {
        "signatures": [{"name": s.get("name"), "severity": s.get("severity"),
                        "description": s.get("description")} for s in report.get("signatures", [])],
        "domains_attempted": sorted({d.get("domain") for d in net.get("domains", []) if d.get("domain")})[:15],
        "hosts_attempted": sorted({h.get("ip") if isinstance(h, dict) else h for h in net.get("hosts", [])} - {None})[:15],
    }


def build_facts(case, use_cape=True):
    t = case["triage"]
    q = next((e for e in case["quarantine"] if e.get("action") == "quarantined"), {})
    payloads = []
    for s in case["scans"]:
        p = {
            "file_name": s.get("filename"),
            "sha256": s.get("sha256"),
            "size_bytes": s.get("size_bytes"),
            "downloaded_from": defang(s.get("source_url")),
            "yara_matches": s.get("yara_matches") or [],
            "virustotal_malicious_engines": s.get("vt_malicious") if s.get("vt_found") else "not found",
            "cape_task_id": s.get("cape_task_id"),
            "cape_malscore": s.get("cape_malscore"),
            "cape_signatures": s.get("cape_signatures"),
            "attack_techniques": [{"id": tid, "name": ATTACK_NAMES.get(tid, ("", ""))[0],
                                   "tactic": ATTACK_NAMES.get(tid, ("", ""))[1]} for tid in s.get("cape_ttps", [])],
            "verdict": s.get("verdict"),
        }
        if use_cape and s.get("cape_task_id"):
            p["cape_detail"] = cape_details(s["cape_task_id"])
        payloads.append(p)
    return {
        "case_id": q.get("qid"),
        "analyzed_at": t["timestamp"],
        "email": {
            "from": t.get("email_from"),
            "subject": t.get("email_subject"),
            "spf": t.get("spf"), "dkim": t.get("dkim"), "dmarc": t.get("dmarc"),
            "links": [defang(u) for u in t.get("urls", [])],
            "triage_findings": t.get("findings", []),
            "triage_score": t.get("triage_score"),
            "triage_verdict": t.get("triage_verdict"),
        },
        "link_fetches": [{"url": defang(e.get("url")), "status": e.get("status")} for e in case["links"]],
        "payloads": payloads,
        "overall_verdict": t.get("verdict"),
        "actions": sorted({e.get("action") for e in case["quarantine"] if e.get("action")}),
        "sandbox_note": "CAPE guest is offline (routing none); network activity is attempted only.",
    }


# ---------------- write the report ----------------

def ask_claude(facts, api_key):
    r = requests.post(API_URL, timeout=120, headers={
        "x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json",
    }, json={
        "model": MODEL, "max_tokens": 2000, "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": "Facts from the pipeline:\n```json\n"
                      + json.dumps(facts, indent=2) + "\n```"}],
    })
    r.raise_for_status()
    return "".join(b.get("text", "") for b in r.json().get("content", []) if b.get("type") == "text").strip()


def ask_ollama(facts):
    """Same prompt, sent to a local model. Free and offline; slower on a CPU-only VM."""
    r = requests.post(f"{OLLAMA_URL}/api/chat", timeout=900, json={
        "model": OLLAMA_MODEL, "stream": False, "options": {"temperature": 0.2, "num_ctx": 8192},
        "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                     {"role": "user", "content": "Facts from the pipeline:\n```json\n"
                      + json.dumps(facts, indent=2) + "\n```"}],
    })
    r.raise_for_status()
    text = r.json().get("message", {}).get("content", "")
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)   # some models show their reasoning
    return text.strip()


def ask_claude_code(facts):
    """Same prompt through the Claude Code CLI, billed to your Claude subscription.

    Runs with every tool disabled, no MCP servers and no saved session: it can only read the facts and
    write text back. Run `claude` once interactively first to log in.
    """
    exe = shutil.which("claude") or shutil.which(os.path.expanduser("~/.local/bin/claude"))
    if not exe:
        raise ValueError("claude CLI not found (install Claude Code and log in once)")
    cmd = [exe, "-p", "--tools", "", "--strict-mcp-config", "--no-session-persistence",
           "--output-format", "text", "--system-prompt", SYSTEM_PROMPT]
    if os.environ.get("CLAUDE_CODE_MODEL"):
        cmd += ["--model", os.environ["CLAUDE_CODE_MODEL"]]
    r = subprocess.run(cmd, input="Facts from the pipeline:\n```json\n" + json.dumps(facts, indent=2) + "\n```",
                       capture_output=True, text=True, timeout=300, cwd=REPORT_DIR)
    if r.returncode != 0 or not r.stdout.strip():
        raise ValueError(f"claude CLI failed: {(r.stderr or r.stdout).strip()[:200]}")
    return r.stdout.strip()


def template_report(facts):
    """Same shape as the AI report, filled in mechanically. Used with --no-ai or when the API fails."""
    e, p = facts["email"], (facts["payloads"] or [{}])[0]
    verdict = (facts["overall_verdict"] or "unknown").upper()
    name = p.get("file_name") or "no payload"
    lines = [f"# {verdict}: \"{e['subject']}\"", "## Summary",
             f"An email from {e['from']} was rated {verdict.lower()} by the pipeline (triage score {e['triage_score']}). "
             + (f"It led to `{name}`, which {p.get('virustotal_malicious_engines')} VirusTotal engines flag "
                f"and which showed {len(p.get('cape_signatures') or [])} suspicious behaviours in the sandbox. " if p else "")
             + "The email was removed from the mailbox and kept in the quarantine vault.",
             "## What happened",
             f"1. Email access: retrieved over OAuth and held while analyzed ({facts['analyzed_at']}).",
             f"2. Static analysis: SPF {e['spf']}, DKIM {e['dkim']}, DMARC {e['dmarc']}; triage score {e['triage_score']}"
             + (f"; payload downloaded, VirusTotal {p.get('virustotal_malicious_engines')} engines." if p else "."),
             f"3. Dynamic analysis: CAPE task {p.get('cape_task_id')}, malscore {p.get('cape_malscore')}.",
             f"4. Action: {', '.join(facts['actions']) or 'none recorded'}.",
             "## Why it was flagged"] + [f"- {f}" for f in e["triage_findings"]] + [
             "## Sandbox behaviour", "| ATT&CK | Technique | Tactic |", "|---|---|---|"] + [
             f"| {t['id']} | {t['name']} | {t['tactic']} |" for t in p.get("attack_techniques", [])] + [
             "## Indicators of compromise", "| Type | Value |", "|---|---|",
             f"| Sender | {e['from']} |"] + [f"| URL | {u} |" for u in e["links"]] + (
             [f"| SHA-256 | {p['sha256']} |", f"| File name | {name} |"] if p.get("sha256") else []) + [
             "## Actions taken"] + [f"- {a}" for a in facts["actions"]] + [
             "## Recommendations",
             "- Block the sender address and the file-sharing link at the mail gateway.",
             "- Search other mailboxes for the same subject, sender and payload hash.",
             "- Remind staff that IT never sends software updates as download links."]
    return "\n".join(lines) + "\n"


def summary_of(report_md):
    """Headline and the Summary paragraph, for printing in the terminal."""
    head = re.search(r"^#\s+(.+)$", report_md, re.M)
    summ = re.search(r"^##\s+Summary\s*\n(.+?)(?=^##\s|\Z)", report_md, re.M | re.S)
    return (head.group(1).strip() if head else ""), (summ.group(1).strip() if summ else "")


def run(subject=None, use_ai=True, use_cape=True, log_file=LOG_FILE):
    """Build, save and return (path, headline, summary, written_by)."""
    facts = build_facts(gather_case(load_events(log_file), subject), use_cape=use_cape)
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    backend = os.environ.get("AI_BACKEND", "claude" if api_key else "none").lower()
    report, by = None, "template"
    if use_ai and backend != "none":
        try:
            if backend == "ollama":
                report, by = ask_ollama(facts), f"{OLLAMA_MODEL} (local, Ollama)"
            elif backend == "claude-code":
                os.makedirs(REPORT_DIR, mode=0o700, exist_ok=True)
                report, by = ask_claude_code(facts), "Claude via Claude Code"
            elif api_key:
                report, by = ask_claude(facts, api_key), f"Claude ({MODEL})"
        except (requests.RequestException, ValueError, subprocess.TimeoutExpired) as e:
            print(f"  AI report failed ({e}); writing the template report instead")
    if not report:
        report = template_report(facts)

    os.makedirs(REPORT_DIR, mode=0o700, exist_ok=True)
    name = facts["case_id"] or datetime.now().strftime("report-%Y%m%d-%H%M%S")
    path = os.path.join(REPORT_DIR, f"{name}.md")
    with open(path, "w") as f:
        f.write(report + f"\n---\n_Written by {by} from analyzer log events. Verify before acting._\n")
    with open(os.path.join(REPORT_DIR, f"{name}.facts.json"), "w") as f:
        json.dump(facts, f, indent=2)
    headline, summary = summary_of(report)
    return path, headline, summary, by


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Write an incident report for an analyzed email")
    ap.add_argument("--subject", help="subject of the email (default: the latest one in the log)")
    ap.add_argument("--no-ai", action="store_true", help="template report only, no API call")
    ap.add_argument("--no-cape", action="store_true", help="don't fetch extra detail from CAPE")
    ap.add_argument("--log", default=LOG_FILE, help="analyzer log file")
    a = ap.parse_args()
    path, headline, summary, by = run(a.subject, not a.no_ai, not a.no_cape, a.log)
    print(f"\n{headline}\n\n{summary}\n\nReport: {path}  (written by {by})")
