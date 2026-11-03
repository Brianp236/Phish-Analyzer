"""Terminal look for new_analyzer.py: the five analysis stages.

    Email Access -> Static Analysis -> Dynamic Analysis -> Action -> Report

The analyzer calls these functions instead of print(). Chatty helpers
(vault, linkfetch, triage, CAPE polling) run inside ui.quiet(), which sends
their print() output to logs/console.log instead of the screen, so the
terminal only shows the clean stage view. Run with --plain to get the old
line-by-line output back for debugging.
"""
import contextlib
import io
import os
import re
import sys
import time

from rich import box
from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

STAGES = ["Email Access", "Static Analysis", "Dynamic Analysis", "Action", "Report"]
ACCENT, MUTED, DIM = "cyan", "grey62", "grey42"
STATUS_COLOUR = {"MALICIOUS": "red", "SUSPICIOUS": "yellow", "CLEAN": "green", "DONE": "green",
                 "SKIPPED": "grey50", "FAILED": "red", "NO FILE": "grey50"}
CONSOLE_LOG = os.path.expanduser("~/analyzer/logs/console.log")

ATTACK_NAMES = {
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1055": ("Process Injection", "Privilege Escalation"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1553": ("Subvert Trust Controls", "Defense Evasion"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1112": ("Modify Registry", "Defense Evasion"),
    "T1497": ("Virtualization/Sandbox Evasion", "Defense Evasion"),
    "T1547": ("Boot or Logon Autostart Execution", "Persistence"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1012": ("Query Registry", "Discovery"),
    "T1106": ("Native API", "Execution"),
    "T1129": ("Shared Modules", "Execution"),
    "T1140": ("Deobfuscate/Decode Files or Information", "Defense Evasion"),
    "T1027.002": ("Software Packing", "Defense Evasion"),
    "T1553.002": ("Code Signing", "Defense Evasion"),
    "T1055.012": ("Process Hollowing", "Defense Evasion"),
    "T1036.005": ("Match Legitimate Name or Location", "Defense Evasion"),
    "T1071.001": ("Web Protocols", "Command and Control"),
    "T1497.001": ("System Checks", "Defense Evasion"),
}

# Rich writes to the real terminal, so redirecting print() in quiet() never hides it.
console = Console(file=sys.__stdout__, highlight=False, width=min(110, Console(file=sys.__stdout__).width))
PLAIN = False
_run_start = None


def set_plain(on):
    global PLAIN
    PLAIN = on


def say(*parts):
    """Print one line in the stage view (ignored in --plain mode, where the old prints show)."""
    if not PLAIN:
        console.print(Text.assemble(*parts))


@contextlib.contextmanager
def quiet():
    """Hide print() output from helper code; keep it in logs/console.log."""
    if PLAIN:
        yield
        return
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            yield
    finally:
        text = buf.getvalue()
        if text:
            os.makedirs(os.path.dirname(CONSOLE_LOG), exist_ok=True)
            with open(CONSOLE_LOG, "a") as f:
                f.write(text)


@contextlib.contextmanager
def working(message):
    """Spinner while a step runs. Yields a function that updates the spinner text."""
    if PLAIN:
        yield lambda text: None
        return
    with console.status(f"[{ACCENT}]{message}", spinner="dots") as status:
        yield lambda text: status.update(f"[{ACCENT}]{message}[/]  [{DIM}]{text}")


def _took(seconds):
    if seconds is None:
        return ""
    return f"{seconds:.1f} s" if seconds < 60 else f"{int(seconds // 60)} m {int(seconds % 60):02d} s"


# ---------------- page furniture ----------------

def flow(upto):
    """Email Access → Static Analysis → ... with finished stages ticked."""
    t = Text("   ")
    for i, name in enumerate(STAGES, 1):
        style = f"bold {ACCENT}" if i == upto else ("green" if i < upto else DIM)
        t.append(("✓ " if i < upto else "● " if i == upto else "○ ") + name, style=style)
        if i < len(STAGES):
            t.append("  →  ", style=DIM)
    return t


def header():
    global _run_start
    _run_start = time.monotonic()
    if PLAIN:
        return
    top = Table.grid(expand=True)
    top.add_column()
    top.add_column(justify="right")
    top.add_row(Text.assemble(("PHISH ANALYZER", f"bold {ACCENT}"), ("  │  Blue Team", MUTED)),
                Text(time.strftime("%Y-%m-%d  %H:%M:%S"), style=DIM))
    console.print(top)
    console.print(Rule(style=ACCENT))
    console.print(flow(0))


def stage(n, status, seconds=None):
    if PLAIN:
        print(f"\n== STAGE {n}/5 {STAGES[n - 1].upper()}: {status} ==")
        return
    g = Table.grid(expand=True)
    g.add_column()
    g.add_column(justify="right")
    g.add_row(Text.assemble((f"STAGE {n}/5  ", DIM), (STAGES[n - 1].upper(), f"bold {ACCENT}")),
              Text.assemble((status, f"bold {STATUS_COLOUR.get(status, 'white')}"), (f"   {_took(seconds)}", DIM)))
    console.print()
    console.print(g)
    console.print(Rule(style="grey23"))


def check(text, extra="", ok=True, extra_style=DIM):
    mark, colour = ("✓", "green") if ok else ("✗", "red")
    say("   ", (f"{mark} ", colour), text, (f"  {extra}" if extra else "", extra_style))


def email_meta(subject, sender, n=None, total=None, recipient=None):
    if PLAIN:
        return
    meta = Table.grid(padding=(0, 2))
    meta.add_column(style=MUTED, justify="right")
    meta.add_column()
    if total and total > 1:
        meta.add_row("Email", Text(f"{n} of {total}", style="bold"))
    meta.add_row("Subject", Text(subject or "(no subject)", style="bold"))
    meta.add_row("From", sender or "")
    if recipient:
        meta.add_row("To", recipient)
    console.print(Padding(meta, (1, 0, 0, 3)))


# ---------------- stage bodies ----------------

def score_bar(score, suspicious_at, malicious_at, top=15, width=24):
    colour = "red" if score >= malicious_at else "yellow" if score >= suspicious_at else "green"
    filled = round(width * min(max(score, 0), top) / top)
    return (Text("█" * filled, style=colour) + Text("░" * (width - filled), style="grey35")
            + Text(f"  {score}", style=f"bold {colour}"))


def triage_block(report, suspicious_at, malicious_at):
    if PLAIN:
        return
    auth = report.get("auth", {})
    passed = [k for k in ("spf", "dkim", "dmarc") if str(auth.get(k, "")).lower() == "pass"]
    line = Text("   Sender     ", style=MUTED)
    for k in ("spf", "dkim", "dmarc"):
        v = str(auth.get(k, "none")).lower()
        line.append(f"{k.upper()} ")
        line.append(v, style="green" if v == "pass" else "red")
        line.append("   ")
    console.print(line)

    shown = [f for f in report["findings"] if f["points"] > 0 and not f["check"].endswith(("_fail", "_none"))]
    if shown:
        console.print(Text("   Findings", style=MUTED))
    for f in shown:
        g = Table.grid(expand=True)
        g.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        g.add_column(justify="right", width=6)
        g.add_row(Text.assemble("     ", ("▪ ", "yellow"), f["detail"]), Text(f"+{f['points']}", style="yellow"))
        console.print(g)
    console.print(Text("   Risk       ", style=MUTED) + score_bar(report["score"], suspicious_at, malicious_at)
                  + Text(f"   malicious ≥ {malicious_at}", style=DIM))


def file_lines(item, size_bytes, sha256):
    src = "link → isolated browser" if item.get("source_url") else "attachment"
    size = f"{size_bytes / 1024:.0f} KB" if size_bytes >= 1024 else f"{size_bytes} B"
    say("   ", ("File       ", MUTED), (os.path.basename(item["path"]), "bold"), (f"  {size}", MUTED),
        (f"   from {src}", DIM))
    say("   ", ("SHA-256    ", MUTED), (f"{sha256[:8]}…{sha256[-8:]}", DIM))


def yara_line(hits, loaded):
    if not loaded:
        return
    if hits:
        say("   ", ("YARA       ", MUTED), (f"{len(hits)} rule(s) matched", "bold red"), (f"   {', '.join(hits[:3])}", DIM))
    else:
        say("   ", ("YARA       ", MUTED), ("no rule matched", ""))


def vt_line(stats):
    if stats is None:
        say("   ", ("VirusTotal ", MUTED), ("not seen before", "bold yellow"), ("   new or targeted file", DIM))
    elif stats["malicious"]:
        say("   ", ("VirusTotal ", MUTED), (str(stats["malicious"]), "bold red"), (" security vendors flag this file", ""))
    else:
        say("   ", ("VirusTotal ", MUTED), ("0", "bold green"), (" vendors flag this file", ""))


def no_files_line():
    say("   ", ("No attachment or downloadable file; judged on the email alone", MUTED))


def cape_block(cape, filename):
    if PLAIN:
        return
    if not cape:
        say("   ", ("✗ ", "red"), ("Sandbox gave no result", ""), (f"   {filename}: rejected, failed or timed out", DIM))
        return
    say("   ", ("Detonated ", MUTED), (filename, "bold"), (" in an offline Windows 10 sandbox", MUTED),
        (f"   task {cape['task_id']}", DIM))
    say("   ", ("Malscore ", MUTED), (str(cape["malscore"]), "bold"), ("    Signatures ", MUTED),
        (str(len(cape["signatures"])), "bold"), ("    High severity ", MUTED), (str(len(cape["high_severity"])), "bold"))
    if cape["ttps"]:
        t = Table.grid(padding=(0, 3))
        t.add_column(style="bold magenta")
        t.add_column()
        t.add_column(style=DIM)
        for tid in cape["ttps"][:8]:
            name, tactic = ATTACK_NAMES.get(tid) or ATTACK_NAMES.get(tid.split(".")[0], ("", ""))
            t.add_row(tid, name, tactic)
        console.print(Padding(t, (1, 0, 0, 3)))
        if len(cape["ttps"]) > 8:
            say("   ", (f"+ {len(cape['ttps']) - 8} more techniques in the CAPE report", DIM))


def report_panel(verdict, headline, summary, path=None, by=None):
    verdict = verdict.upper()
    took = _took(time.monotonic() - _run_start) if _run_start else ""
    if PLAIN:
        print(f"\n{verdict}: {headline}\n{summary}\n{('Report: ' + path) if path else ''}")
        return
    colour = STATUS_COLOUR.get(verdict, "white")
    headline = re.sub(rf"^{verdict}\s*[:\-]\s*", "", headline.strip(), flags=re.I)   # the badge already says it
    summary = re.sub(r"`([^`]+)`|\*\*([^*]+)\*\*", lambda m: m.group(1) or m.group(2), summary)   # drop markdown marks
    body = [Text.assemble((f" {verdict} ", f"bold white on {colour}"), "   ", (headline, "bold")), Text(), Text(summary)]
    if path:
        body += [Text(), Text.assemble(("Full report  ", MUTED), (path.replace(os.path.expanduser("~/analyzer/"), ""), "bold"),
                                       ("   timeline · indicators · ATT&CK · recommendations", DIM))]
    title = "[bold]INCIDENT SUMMARY" if verdict != "CLEAN" else "[bold]RESULT"
    sub = f"[grey50]{('AI analysis by ' + by) if by and by != 'template' else 'written from the analysis log'}"
    console.print()
    console.print(Panel(Group(*body), title=title, title_align="left", subtitle=sub, subtitle_align="right",
                        border_style=colour, box=box.ROUNDED, padding=(1, 3)))
    console.print(flow(6))
    console.print(Text(f"   total {took}", style=DIM), justify="right")
