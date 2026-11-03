"""Download the files that links in an email point to, so YARA/VirusTotal/CAPE can scan them.

Only the analyzer VM touches the link and nothing downloaded is opened or run.
The CAPE sandbox stays offline. Used by the analyzer as:
    attachments += linkfetch.fetch_link_payloads(triage_report, log_event)
"""
import os
import re
import hashlib
import socket
import ipaddress
import requests
from email.message import Message
from urllib.parse import urlparse, urljoin, unquote

# Link payloads: download files that email links point to, so YARA/VT/CAPE can scan them.
FETCH_LINKS = True
FETCH_MAX_LINKS = 5               # per email
FETCH_MAX_BYTES = 50 * 1024 * 1024
# Private/lab addresses are refused (stops a link from poking the CAPE API or your LAN).
# Add the red team's download server here if it lives on your LAN or Tailscale, e.g. "100.101.102.103".
FETCH_ALLOW_HOSTS = []

# Share pages (LimeWire, Google Drive, Dropbox...) only hand over the file after JavaScript runs
# and someone clicks "Download". For those, open the page in an invisible Chromium on this VM.
FETCH_BROWSER = True
BROWSER_TIMEOUT_MS = 45000
BROWSER_EXECUTABLE = os.environ.get("LINKFETCH_CHROMIUM")   # None = the one `playwright install` set up
DOWNLOAD_BUTTON_TEXT = r"download|descargar|get file|save"
FILE_ENTRY_TEXT = r"\.(exe|msi|zip|rar|7z|iso|img|js|vbs|ps1|bat|scr|lnk|docm|xlsm|pdf|dmg|pkg)\b"  # file names on share pages
CONSENT_BUTTON_TEXT = r"^\s*(accept|accept all|accept all cookies|allow all|allow all cookies|agree|i agree|got it|ok|continue|confirm|confirm my choices)\s*$"
CONSENT_SELECTORS = "#onetrust-accept-btn-handler, .onetrust-close-btn-handler, .save-preference-btn-handler"  # CookiePro/OneTrust
BROWSER_HEADLESS = os.environ.get("LINKFETCH_HEADLESS", "1") != "0"   # LINKFETCH_HEADLESS=0 shows the window
SCREENSHOT_DIR = os.path.expanduser("~/analyzer/link_screenshots")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"


def _fetch_allowed(url):
    """Refuse links that resolve to this machine, the LAN or Tailscale unless allow-listed."""
    host = urlparse(url).hostname or ""
    if host in FETCH_ALLOW_HOSTS:
        return True, ""
    try:
        addrs = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        return False, "host does not resolve"
    for addr in addrs:
        ip = ipaddress.ip_address(addr)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip in ipaddress.ip_network("100.64.0.0/10"):
            return False, f"{host} resolves to internal address {addr} (add it to FETCH_ALLOW_HOSTS if it is the red team server)"
    return True, ""


def _looks_like_file(resp, url):
    disposition = resp.headers.get("Content-Disposition", "")
    ctype = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
    if "attachment" in disposition.lower():
        return True
    if ctype and ctype not in ("text/html", "application/xhtml+xml"):
        return True
    return os.path.splitext(urlparse(url).path)[1].lower() not in ("", ".html", ".htm", ".php", ".asp", ".aspx")


def _download_name(resp, url):
    msg = Message()
    msg["Content-Disposition"] = resp.headers.get("Content-Disposition", "")
    name = msg.get_filename() or unquote(os.path.basename(urlparse(url).path)) or "download"
    return "link_" + os.path.basename(name).replace("..", "_")


def fetch_link_payloads(report, log_event, save_dir="attachments"):
    """Download files that the email's links point to. Nothing is opened or run.

    Only the analyzer VM touches the link; the CAPE sandbox stays offline.
    Web pages are skipped (they are judged by the link checks); real files are
    returned in the same shape as extract_attachments() so they go through
    YARA, VirusTotal and CAPE like any attachment.
    """
    if not FETCH_LINKS:
        return []
    os.makedirs(save_dir, exist_ok=True)
    saved = []
    for entry in report["urls"][:FETCH_MAX_LINKS]:
        url, status, info = entry["url"], None, {}
        try:
            for _ in range(5):  # follow redirects by hand so every hop is checked
                ok, why = _fetch_allowed(url)
                if not ok:
                    status = f"blocked: {why}"
                    break
                resp = requests.get(url, stream=True, timeout=(10, 30), allow_redirects=False,
                                    headers={"User-Agent": UA})
                if resp.is_redirect:
                    url = urljoin(url, resp.headers["Location"])
                    resp.close()
                    continue
                if resp.status_code != 200:
                    status = f"http {resp.status_code}"
                elif not _looks_like_file(resp, url):
                    status = "web page, not a file"
                else:
                    path = os.path.join(save_dir, _download_name(resp, url))
                    size = 0
                    with open(path, "wb") as f:
                        for chunk in resp.iter_content(65536):
                            size += len(chunk)
                            if size > FETCH_MAX_BYTES:
                                break
                            f.write(chunk)
                    os.chmod(path, 0o600)
                    if size > FETCH_MAX_BYTES:
                        os.remove(path)
                        status = f"too large (> {FETCH_MAX_BYTES // 1048576} MB)"
                    else:
                        status = "downloaded"
                        info = {"filename": os.path.basename(path), "size_bytes": size,
                                "content_type": resp.headers.get("Content-Type", "")}
                        saved.append({"path": path, "email_from": report["sender"]["from"],
                                      "email_subject": report["subject"], "source_url": entry["url"]})
                resp.close()
                break
            else:
                status = "too many redirects"
        except requests.RequestException as e:
            status = f"failed: {e.__class__.__name__}"

        if status == "web page, not a file" and FETCH_BROWSER:
            # The original link, #fragment included: LimeWire keeps the decryption key there.
            path, status, info = _browser_download(entry["url"], save_dir)
            if path:
                saved.append({"path": path, "email_from": report["sender"]["from"],
                              "email_subject": report["subject"], "source_url": entry["url"]})

        print(f"  Link {entry['url']}: {status}")
        log_event({"event_type": "link_fetch", "email_subject": report["subject"],
                   "url": entry["url"], "final_url": url, "status": status, **info})
    return saved


def _dismiss_popups(page, PwError):
    """Close cookie / privacy popups that cover the real button.

    They often live in their own iframe and their CONFIRM may be a link or a
    div rather than a button, so look in every frame for all three.
    """
    consent_name = re.compile(CONSENT_BUTTON_TEXT, re.I)
    for _ in range(3):  # closing one popup can reveal another
        closed = False
        for frame in page.frames:
            try:
                btn = (frame.locator(CONSENT_SELECTORS)
                       .or_(frame.get_by_role("button", name=consent_name))
                       .or_(frame.get_by_role("link", name=consent_name))
                       .or_(frame.get_by_text(consent_name)))
                for i in range(min(btn.count(), 5)):
                    if btn.nth(i).is_visible():
                        btn.nth(i).click(timeout=3000)
                        closed = True
                        break
            except PwError:
                continue
            if closed:
                break
        if not closed:
            page.keyboard.press("Escape")
            return
        page.wait_for_timeout(1500)


def _browser_download(url, save_dir):
    """Open a share page in headless Chromium, click its download button, keep the file.

    The file is saved, never opened. Every request the page makes goes through
    the same internal-address block as normal downloads. A screenshot of the page
    is kept as evidence. Returns (path or None, status, info).
    """
    try:
        from playwright.sync_api import sync_playwright, Error as PwError
    except ImportError:
        return None, "web page (browser step off: pip install playwright)", {}

    allowed_hosts = {}

    def guard(route):
        req_url = route.request.url
        host = urlparse(req_url).hostname
        if req_url.startswith(("http://", "https://")):
            if host not in allowed_hosts:
                allowed_hosts[host] = _fetch_allowed(req_url)[0]
            if not allowed_hosts[host]:
                return route.abort()
        return route.continue_()

    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    shot = os.path.join(SCREENSHOT_DIR, hashlib.sha256(url.encode()).hexdigest()[:16] + ".png")
    info = {"method": "browser", "screenshot": shot}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=BROWSER_HEADLESS, executable_path=BROWSER_EXECUTABLE,
                                        args=["--disable-blink-features=AutomationControlled"])
            try:
                ctx = browser.new_context(accept_downloads=True, user_agent=UA)
                ctx.route("**/*", guard)
                # Share sites may save through the "Save as" file picker, which a headless
                # browser can't answer. Without it they fall back to a normal download.
                ctx.add_init_script("delete window.showSaveFilePicker;"
                                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});")
                page = ctx.new_page()
                downloads = []
                # The site may start the download in a new tab, so listen on every tab.
                ctx.on("page", lambda pg: pg.on("download", lambda d: downloads.append(d)))
                page.on("download", lambda d: downloads.append(d) if d not in downloads else None)
                try:
                    page.goto(url, wait_until="networkidle", timeout=BROWSER_TIMEOUT_MS)
                except PwError:
                    pass  # slow pages still get a chance below
                page.wait_for_timeout(3000)  # some pages start the download on their own

                # Cookie / consent banners can cover the real button.
                _dismiss_popups(page, PwError)
                try:
                    page.wait_for_load_state("networkidle", timeout=10000)
                except PwError:
                    pass

                # Try real buttons/links first, then any text saying "download", then the
                # file entry itself (some pages only show the button after you open the file).
                # Each element is clicked once; up to 4 rounds because some flows need
                # file -> Download -> confirm.
                name = re.compile(DOWNLOAD_BUTTON_TEXT, re.I)
                clicked = set()
                for _ in range(4):
                    if downloads:
                        break
                    _dismiss_popups(page, PwError)  # some popups appear late
                    groups = [
                        page.get_by_role("button", name=name).or_(page.get_by_role("link", name=name)),
                        page.get_by_text(name),
                        page.get_by_text(re.compile(FILE_ENTRY_TEXT, re.I)),
                    ]
                    progressed = False
                    for g, group in enumerate(groups):
                        for i in range(min(group.count(), 6)):
                            el = group.nth(i)
                            try:
                                if not el.is_visible():
                                    continue
                                key = el.evaluate("e => e.outerHTML.slice(0, 300)")
                                if key in clicked:
                                    continue
                                clicked.add(key)
                                progressed = True
                                try:
                                    el.click(timeout=5000)
                                except PwError:
                                    # Something (an ad, a popup) is on top of it: click it directly.
                                    el.evaluate("e => e.click()")
                                for _ in range(40 if g == 0 else 16):  # up to 20 s / 8 s
                                    if downloads:
                                        break
                                    page.wait_for_timeout(500)
                                if downloads:
                                    break
                            except PwError:
                                continue
                        if downloads or progressed:
                            break  # page may have changed: look again from the top
                    if not progressed:
                        break
                    page.wait_for_timeout(1000)
                page.screenshot(path=shot, full_page=True)

                if not downloads:
                    # Record what the page offered, so the button label can be added.
                    texts = page.locator("button, a, [role=button]").all_inner_texts()
                    texts = sorted({t.strip().replace("\n", " ")[:40] for t in texts if t.strip()})[:25]
                    with open(shot[:-4] + ".txt", "w") as f:
                        f.write(f"{page.url}\n{page.title()}\n\n" + "\n".join(texts) + "\n")
                    info["page_title"] = page.title()
                    return None, (f"web page, no download found in browser "
                                  f"(title: {page.title()[:40]!r}; buttons: {', '.join(texts[:8]) or 'none'})"), info
                d = downloads[0]
                path = os.path.join(save_dir, "link_" + os.path.basename(d.suggested_filename or "download").replace("..", "_"))
                d.save_as(path)
                os.chmod(path, 0o600)
                size = os.path.getsize(path)
                if size > FETCH_MAX_BYTES:
                    os.remove(path)
                    return None, f"too large (> {FETCH_MAX_BYTES // 1048576} MB)", info
                info.update(filename=os.path.basename(path), size_bytes=size)
                return path, "downloaded (browser)", info
            finally:
                browser.close()
    except PwError as e:
        return None, f"browser failed: {str(e).splitlines()[0][:120]}", info
