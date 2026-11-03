#!/usr/bin/env python3
"""
phish_triage.py - Blue team triage for a suspicious .eml file.

Covers the parts of a phishing email the attachment pipeline does not:
  1. Authentication  - SPF / DKIM / DMARC results from the receiving server
  2. Sender identity - From vs Reply-To vs Return-Path, display-name spoofing, lookalike domains
  3. Links           - every URL, where the link text lies about the real target
  4. Attachments     - SHA-256 hashes, risky / double extensions (hand these to the VT + CAPE pipeline)
  5. Content         - urgency / credential-harvesting language

Each check adds points to a risk score; the score becomes a verdict.
Standard library only. Optional: set VT_API_KEY to look up URLs on VirusTotal.

Usage:
  python3 phish_triage.py samples/phish_sample.eml
  python3 phish_triage.py samples/phish_sample.eml --json logs/triage.json
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

# --- Tunable lists (edit these to match the red team's scenario) -------------

BRANDS = ["paypal", "microsoft", "office365", "google", "apple", "amazon",
          "fbi", "irs", "docusign", "wellsfargo", "chase", "bankofamerica",
          "zoom", "teams", "outlook", "adobe", "dropbox", "okta", "slack"]
# Free file hosts: legit services, but a favourite way to deliver malware by link.
FILE_SHARING = {"limewire.com", "mega.nz", "mediafire.com", "wetransfer.com", "we.tl", "gofile.io",
                "sendspace.com", "pixeldrain.com", "catbox.moe", "filebin.net", "transfer.sh",
                "dropbox.com", "dropboxusercontent.com", "drive.google.com", "docs.google.com",
                "1drv.ms", "onedrive.live.com", "cdn.discordapp.com", "anonfiles.com", "files.fm"}
# Free webmail: fine for a friend, odd for "your IT department".
FREEMAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
            "aol.com", "proton.me", "protonmail.com", "pm.me", "icloud.com", "gmx.com", "mail.com",
            "yandex.com", "zoho.com", "tutanota.com"}
ROLE_CLAIMS = ["it department", "your it", "it support", "it team", "helpdesk", "help desk",
               "service desk", "security team", "system administrator", "payroll",
               "human resources", "hr department", "accounts payable"]
DOWNLOAD_LURES = ["download and open", "download and install", "open the attachment", "install the update",
                  "run the file", "enable macros", "enable content", "update now", "download the update"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "rb.gy", "cutt.ly"}
RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".html",
                    ".htm", ".iso", ".img", ".lnk", ".docm", ".xlsm", ".jar", ".zip", ".rar"}
URGENCY_PHRASES = ["verify your account", "account will be suspended", "urgent", "immediately",
                   "within 24 hours", "confirm your password", "unusual activity",
                   "click here", "login to restore", "payment failed", "final notice",
                   "asap", "as soon as possible", "out of date", "inform your boss",
                   "your manager will", "action required"]
DEADLINE_RE = re.compile(r"\b(?:within|in the next|in)\s+(?:\d+|one|two|three|24|48)\s+(?:hours?|minutes?|hrs?)\b")

# Points added for each finding; verdict thresholds below.
WEIGHTS = {
    "spf_fail": 2, "dkim_fail": 2, "dmarc_fail": 3, "spf_none": 1, "dkim_none": 1,
    "reply_to_mismatch": 2, "return_path_mismatch": 1, "display_name_spoof": 3,
    "lookalike_domain": 3, "link_text_mismatch": 3, "ip_url": 2, "shortener": 1,
    "punycode": 2, "at_in_url": 2, "risky_attachment": 2, "double_extension": 3,
    "urgency": 1, "vt_malicious_url": 4,
    "file_sharing_link": 2, "link_text_brand_mismatch": 3, "freemail_impersonation": 3, "download_lure": 2,
}
MALICIOUS_AT, SUSPICIOUS_AT = 8, 4

# --- Pretty output (plain text if not a terminal) ----------------------------

COLOR = sys.stdout.isatty()
def c(text, code):
    return f"\033[{code}m{text}\033[0m" if COLOR else text
RED, YELLOW, GREEN, BOLD, DIM = "31;1", "33;1", "32;1", "1", "2"


class Finding:
    def __init__(self, key, detail):
        self.key, self.detail, self.points = key, detail, WEIGHTS.get(key, 0)


# --- Parsing -----------------------------------------------------------------

def load_email(path):
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def domain_of(address):
    """'Name <user@mail.Example.com>' -> 'mail.example.com'"""
    _, addr = parseaddr(address or "")
    return addr.rpartition("@")[2].lower().strip(">") if "@" in addr else ""


def base_domain(host):
    """Rough registrable domain: last two labels (good enough for scoring)."""
    parts = host.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# --- 1. Authentication -------------------------------------------------------

def check_auth(msg):
    """Read SPF/DKIM/DMARC results the receiving mail server already stamped on the message.

    Three cases, scored differently:
      fail / softfail / permerror -> the check ran and the email failed it (full points)
      none                        -> the check ran but the domain has no SPF/DKIM set up (small points)
      no header at all            -> nothing was checked, e.g. an email you sent to yourself (no points)
    """
    findings, results = [], {"spf": "not checked", "dkim": "not checked", "dmarc": "not checked"}
    auth_headers = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    for mech in results:
        m = re.search(rf"\b{mech}=(\w+)", auth_headers, re.I)
        if m:
            results[mech] = m.group(1).lower()

    # Received-SPF looks like "pass (google.com: domain of ...)", the result is the first word.
    received_spf = msg.get("Received-SPF")
    if results["spf"] == "not checked" and received_spf:
        results["spf"] = str(received_spf).split()[0].lower()

    descriptions = {
        "spf": "sending server not authorized for this domain",
        "dkim": "no valid cryptographic signature",
        "dmarc": "domain owner's policy says reject/quarantine",
    }
    for mech, value in results.items():
        if value in AUTH_FAILED:
            findings.append(Finding(f"{mech}_fail", f"{mech.upper()} = {value}: {descriptions[mech]}"))
        elif value == "none" and mech != "dmarc":
            findings.append(Finding(f"{mech}_none", f"{mech.upper()} = none: sender's domain has no {mech.upper()} set up"))
    return results, findings


AUTH_FAILED = {"fail", "softfail", "permerror"}


# --- 2. Sender identity ------------------------------------------------------

def check_sender(msg):
    findings = []
    from_hdr = str(msg.get("From", ""))
    display, _ = parseaddr(from_hdr)
    from_dom = domain_of(from_hdr)
    reply_dom = domain_of(str(msg.get("Reply-To", "")))
    return_dom = domain_of(str(msg.get("Return-Path", "")))

    if reply_dom and base_domain(reply_dom) != base_domain(from_dom):
        findings.append(Finding("reply_to_mismatch", f"Replies go to {reply_dom}, not {from_dom}"))
    if return_dom and base_domain(return_dom) != base_domain(from_dom):
        findings.append(Finding("return_path_mismatch", f"Bounces go to {return_dom}, not {from_dom}"))

    # Display name claims a brand the actual domain does not belong to.
    for brand in BRANDS:
        if brand in display.lower().replace(" ", "") and brand not in from_dom.replace("-", ""):
            findings.append(Finding("display_name_spoof", f'Display name "{display}" but sent from {from_dom}'))
            break

    lookalike = find_lookalike(from_dom)
    if lookalike:
        findings.append(Finding("lookalike_domain", f"{from_dom} imitates '{lookalike}'"))

    sender = {"from": from_hdr, "from_domain": from_dom, "reply_to_domain": reply_dom,
              "return_path_domain": return_dom}
    return sender, findings


HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t", "@": "a"})

def find_lookalike(host):
    """Catch paypa1.com, rnicrosoft.com, paypal-secure-login.com style domains."""
    if not host:
        return None
    name = base_domain(host).split(".")[0]
    normalized = name.translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    for brand in BRANDS:
        if name == brand:
            return None  # the real thing (by name)
        if brand in normalized or (len(brand) >= 5 and edit_distance(normalized, brand) == 1):
            return brand
    return None


def edit_distance(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# --- 3. Links ----------------------------------------------------------------

class LinkCollector(HTMLParser):
    """Collect (href, visible text) pairs from the HTML body."""
    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._text = dict(attrs).get("href"), []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)

def body_parts(msg):
    text, html = "", ""
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() == "text/plain":
            text += part.get_content()
        elif part.get_content_type() == "text/html":
            html += part.get_content()
    return text, html


def check_links(msg):
    text, html = body_parts(msg)
    collector = LinkCollector()
    collector.feed(html)
    pairs = collector.links + [(u, "") for u in URL_RE.findall(text)]

    findings, urls, seen = [], [], set()
    for href, shown in pairs:
        if not href or href in seen or not href.lower().startswith("http"):
            continue
        seen.add(href)
        host = (urlparse(href).hostname or "").lower()
        urls.append({"url": href, "host": host, "link_text": shown})

        shown_host = (urlparse(shown).hostname or "") if URL_RE.match(shown or "") else ""
        if shown_host and base_domain(shown_host) != base_domain(host):
            findings.append(Finding("link_text_mismatch", f'Text says {shown_host} but link goes to {host}'))
        if is_ip(host):
            findings.append(Finding("ip_url", f"Link points at a raw IP address: {href}"))
        if host in SHORTENERS:
            findings.append(Finding("shortener", f"URL shortener hides the destination: {href}"))
        if "xn--" in host:
            findings.append(Finding("punycode", f"Punycode (possible Unicode lookalike) host: {host}"))
        if "@" in (urlparse(href).netloc or ""):
            findings.append(Finding("at_in_url", f"'@' in URL hides the real host: {href}"))
        if any(host == d or host.endswith("." + d) for d in FILE_SHARING):
            findings.append(Finding("file_sharing_link", f"Link goes to a public file-sharing host: {host}"))
        claimed = next((b for b in BRANDS if re.search(rf"\b{b}\b", (shown or "").lower())), None)
        if claimed and claimed not in host.replace("-", "") and not (shown_host and base_domain(shown_host) != base_domain(host)):
            findings.append(Finding("link_text_brand_mismatch", f'Link text says "{shown.strip()}" but goes to {host}'))
        brand = find_lookalike(host)
        if brand and not any(f.key == "lookalike_domain" and host in f.detail for f in findings):
            findings.append(Finding("lookalike_domain", f"Link host {host} imitates '{brand}'"))
    return urls, findings, text + html


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# --- 4. Attachments ----------------------------------------------------------

def check_attachments(msg):
    findings, attachments = [], []
    for part in msg.iter_attachments():
        # Attacker-controlled name: never use it as a path, only display it.
        name = os.path.basename(part.get_filename() or "unnamed")
        data = part.get_payload(decode=True) or b""
        exts = [e.lower() for e in re.findall(r"\.[A-Za-z0-9]{1,5}", name)]
        attachments.append({"filename": name, "size": len(data),
                            "content_type": part.get_content_type(),
                            "sha256": hashlib.sha256(data).hexdigest()})
        if len(exts) >= 2 and exts[-1] in RISKY_EXTENSIONS:
            findings.append(Finding("double_extension", f"{name}: looks like {exts[-2]} but is really {exts[-1]}"))
        elif exts and exts[-1] in RISKY_EXTENSIONS:
            findings.append(Finding("risky_attachment", f"{name}: {exts[-1]} files can run code or host a fake login"))
    return attachments, findings


# --- 5. Content --------------------------------------------------------------

def check_content(msg, body):
    blob = (str(msg.get("Subject", "")) + " " + re.sub(r"<[^>]+>", " ", body)).lower()
    blob = re.sub(r"\s+", " ", blob)
    findings = []

    hits = [p for p in URGENCY_PHRASES if re.search(rf"\b{re.escape(p)}\b", blob)]
    hits += [d for d in DEADLINE_RE.findall(blob) if d not in hits]
    hits = list(dict.fromkeys(hits))
    if hits:
        findings.append(Finding("urgency", f'Pressure language: "{", ".join(hits)}"'))

    lures = [p for p in DOWNLOAD_LURES if p in blob]
    if lures:
        findings.append(Finding("download_lure", f'Tells the reader to download/run something: "{", ".join(lures)}"'))

    from_hdr = str(msg.get("From", ""))
    from_dom = domain_of(from_hdr)
    if from_dom in FREEMAIL:
        display = parseaddr(from_hdr)[0].lower()
        claims = [r for r in ROLE_CLAIMS if re.search(rf"\b{re.escape(r)}\b", display + " " + blob)]
        if claims:
            findings.append(Finding("freemail_impersonation",
                                    f'Claims to be "{claims[0]}" but sent from free webmail ({from_dom})'))
    return findings


# --- Optional: VirusTotal URL lookup -----------------------------------------

def vt_url_lookup(url, api_key):
    """Look up an already-known URL report (does not submit anything)."""
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                                 headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            stats = json.load(resp)["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0)
    except Exception:
        return None  # 404 = never seen, or no network; not a verdict either way


# --- Verdict + report --------------------------------------------------------

def decide_verdict(score):
    if score >= MALICIOUS_AT:
        return "MALICIOUS"
    if score >= SUSPICIOUS_AT:
        return "SUSPICIOUS"
    return "CLEAN"


def triage(path, use_vt=True):
    msg = load_email(path)
    auth, f_auth = check_auth(msg)
    sender, f_sender = check_sender(msg)
    urls, f_links, body = check_links(msg)
    attachments, f_att = check_attachments(msg)
    f_content = check_content(msg, body)

    api_key = os.environ.get("VT_API_KEY")
    if use_vt and api_key:
        for u in urls:
            u["vt_malicious"] = vt_url_lookup(u["url"], api_key)
            if u["vt_malicious"]:
                f_links.append(Finding("vt_malicious_url", f"VirusTotal: {u['vt_malicious']} engines flag {u['url']}"))

    sections = [("Authentication", f_auth), ("Sender", f_sender), ("Links", f_links),
                ("Attachments", f_att), ("Content", f_content)]
    score = sum(f.points for _, fs in sections for f in fs)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "phish_triage",
        "file": os.path.basename(path),
        "subject": str(msg.get("Subject", "")),
        "message_id": str(msg.get("Message-ID", "")).strip(),
        "auth": auth, "sender": sender, "urls": urls, "attachments": attachments,
        "findings": [{"section": s, "check": f.key, "points": f.points, "detail": f.detail}
                     for s, fs in sections for f in fs],
        "score": score,
        "verdict": decide_verdict(score),
    }, sections


def print_report(r, sections):
    line = "=" * 64
    print(c(line, DIM))
    print(c("  PHISHING TRIAGE REPORT", BOLD))
    print(c(line, DIM))
    print(f"  File    : {r['file']}")
    print(f"  Subject : {r['subject']}")
    print(f"  From    : {r['sender']['from']}")
    a = r["auth"]
    print(f"  Auth    : SPF={a['spf']}  DKIM={a['dkim']}  DMARC={a['dmarc']}")
    for title, findings in sections:
        print()
        print(c(f"[{title}]", BOLD))
        if not findings:
            print(c("  ok - nothing suspicious", GREEN))
        for f in findings:
            print(f"  {c('!', YELLOW)} {f.detail} {c(f'(+{f.points})', DIM)}")
    if r["urls"]:
        print()
        print(c("[IOCs - URLs]", BOLD))
        for u in r["urls"]:
            vt = ""
            if "vt_malicious" in u:
                vt = "  VT: not found" if u["vt_malicious"] is None else f"  VT malicious={u['vt_malicious']}"
            print(f"  {defang(u['url'])}{vt}")
    if r["attachments"]:
        print()
        print(c("[IOCs - attachment SHA-256, hand off to VirusTotal + CAPE]", BOLD))
        for att in r["attachments"]:
            print(f"  {att['sha256']}  {att['filename']} ({att['size']} bytes)")
    color = {"MALICIOUS": RED, "SUSPICIOUS": YELLOW, "CLEAN": GREEN}[r["verdict"]]
    print()
    print(c(line, DIM))
    print(c(f"  VERDICT: {r['verdict']}   (risk score {r['score']}; "
            f"suspicious >= {SUSPICIOUS_AT}, malicious >= {MALICIOUS_AT})", color))
    print(c(line, DIM))


def defang(url):
    """Make a URL safe to display or share: http -> hxxp, . -> [.]"""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def main():
    ap = argparse.ArgumentParser(description="Triage a suspicious .eml file")
    ap.add_argument("eml", help="path to the .eml file")
    ap.add_argument("--json", metavar="LOGFILE", help="append one JSON line per email (Wazuh-friendly)")
    ap.add_argument("--no-vt", action="store_true", help="skip VirusTotal even if VT_API_KEY is set")
    args = ap.parse_args()

    report, sections = triage(args.eml, use_vt=not args.no_vt)
    print_report(report, sections)
    if args.json:
        with open(args.json, "a") as f:
            f.write(json.dumps(report) + "\n")
        print(f"\n  Logged to {args.json}")
    sys.exit({"CLEAN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}[report["verdict"]])


if __name__ == "__main__":
    main()
