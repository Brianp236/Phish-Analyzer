# Building the lab

This guide builds the analyzer VM from scratch: the CAPE sandbox, the analyzer itself, Gmail access,
VirusTotal, the Wazuh agent and the optional AI report. Hardware used is listed under **Lab specs** in the
main README.

Run everything below on the analyzer VM unless a step says otherwise.

## 1. The analyzer VM

- Ubuntu (22.04 or 24.04) in VMware, with at least 4 vCPUs, 12 GB RAM and 100 GB disk.
- Turn on nested virtualization (**VM Settings → Processors → Virtualize Intel VT-x/EPT or AMD-V/RVI**). The
  CAPE guest is a KVM VM running inside this one.
- Python 3.10 or newer.

## 2. CAPEv2 sandbox

Install CAPEv2 and a Windows 10 KVM guest by following the three-part guide by
[@rizqisetyokus](https://medium.com/@rizqisetyokus):
[part 1](https://medium.com/@rizqisetyokus/building-capev2-automated-malware-analysis-sandbox-part-1-da2a6ff69cdb),
[part 2](https://medium.com/@rizqisetyokus/building-capev2-automated-malware-analysis-sandbox-part-2-0c47e4b5cbcd),
[part 3](https://medium.com/@rizqisetyokus/building-capev2-automated-malware-analysis-sandbox-part-3-d5535a0ab6f6).

What the analyzer expects:

- The guest is labelled `win10` in `/opt/CAPEv2/conf/kvm.conf`. If you use another label, change
  `machine="win10"` in `submit_to_cape()` in `new_analyzer.py`.
- The guest has a clean snapshot that CAPE reverts to before each run.
- The CAPE API answers at `http://localhost:8000/apiv2` (`CAPE_URL` in `new_analyzer.py`).
- The services are running: `sudo systemctl status cape cape-processor cape-web`.

The exact settings changed from CAPE's defaults (kvm.conf, cuckoo.conf, auxiliary.conf, reporting.conf, api.conf)
are in [`sandbox/cape-config.md`](../sandbox/cape-config.md).

Then cut the guest off from every network, as described in [`sandbox/isolation.md`](../sandbox/isolation.md).

## 3. Install the analyzer

The scripts live in `~/analyzer/`, with the OAuth files in `~/analyzer/oauth/`. Logs, the quarantine vault and
reports are created under `~/analyzer/` on first run.

```bash
git clone https://github.com/<you>/Phish-Analyzer.git && cd Phish-Analyzer
pip install -r requirements.txt
python3 -m playwright install chromium
sudo python3 -m playwright install-deps chromium      # system libraries Chromium needs

mkdir -p ~/analyzer/oauth && chmod 700 ~/analyzer ~/analyzer/oauth
cp analyzer/*.py ~/analyzer/
cp oauth/*.py ~/analyzer/oauth/
cp secrets.env.example ~/analyzer/secrets.env && chmod 600 ~/analyzer/secrets.env
```

## 4. VirusTotal

Create a free account at virustotal.com, copy your API key from your profile, and put it in
`~/analyzer/secrets.env` as `VT_API_KEY`. The free tier allows 4 lookups a minute, which is plenty for one inbox.

## 5. Gmail access (OAuth 2.0)

The analyzer reads mail over IMAP and signs in with an OAuth token instead of a password.

**In the Google Cloud console** (<https://console.cloud.google.com>, free, no billing needed):

1. Create a project, for example `phish-analyzer`.
2. **APIs & Services → Library:** enable the **Gmail API**.
3. **Google Auth Platform → Branding:** app name `Phish Analyzer`, your email as support and developer contact.
4. **Audience:** user type **External**. Under **Test users**, add the Gmail address the analyzer will watch.
5. **Data Access → Add or remove scopes:** add `https://mail.google.com/` manually. It's the only scope Gmail
   accepts for IMAP.
6. **Clients → Create client:** type **Desktop app**. Download the JSON and save it on the VM as
   `~/analyzer/oauth/client_secret.json` with `chmod 600`.

While the app is in **Testing**, the token expires after 7 days. Publishing it (**Audience → Publish app**) removes
that limit; Google then shows an "unverified app" warning at sign-in, which is fine for an app only you use.

**Sign in once:**

```bash
cd ~/analyzer/oauth && python3 auth_setup.py
```

A browser opens. Sign in as the inbox account and click **Allow**. `token.json` is saved next to the script
with `chmod 600`.

If the inbox owner is on another machine, run `python3 auth_remote.py` instead. It writes a sign-in link to
`login_url.txt`; the owner opens it, signs in, and sends back the `http://localhost:8080/...` address their
browser lands on. Paste that in, and the token is saved without their password ever reaching the VM.

**Gmail setting:** in Gmail, go to **Settings → See all settings → Forwarding and POP/IMAP**. Make sure IMAP is on
and **Auto-Expunge** is on, which is the default. The vault deletes quarantined mail through Trash and then checks
All Mail to confirm it's gone.

Finally, set `GMAIL_USER` in `~/analyzer/secrets.env` to the inbox address.

| Error | Cause | Fix |
|---|---|---|
| `Error 403: access_denied` in the browser | The account isn't a test user | Add it under Audience → Test users |
| `redirect_uri_mismatch` | Client type isn't Desktop app | Create a Desktop app client and download it again |
| `invalid_grant` or an `auth_failed` event | Token expired (7 days in Testing) or revoked | Run `auth_setup.py` again |
| `AUTHENTICATE failed` from IMAP | `GMAIL_USER` doesn't match the signed-in account | Fix `GMAIL_USER` |

## 6. Wazuh agent

The analyzer writes one JSON event per line to `~/analyzer/logs/analyzer.json`. A Wazuh agent ships it to your
Wazuh manager.

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
# The agent version must match the manager's version or be older
sudo WAZUH_MANAGER="<manager-ip>" WAZUH_AGENT_NAME="phish-analyzer" apt install wazuh-agent=<4.x.x-1>
sudo apt-mark hold wazuh-agent
```

Add this inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`, using the full path to your home folder:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/home/<user>/analyzer/logs/analyzer.json</location>
</localfile>
```

```bash
sudo systemctl enable --now wazuh-agent && sudo systemctl restart wazuh-agent
```

The VM must reach the manager on TCP 1514 (events) and 1515 (enrollment). Example manager rules are in
[`wazuh/local_rules.example.xml`](../wazuh/local_rules.example.xml). To test them, paste a line from
`analyzer.json` into `sudo /var/ossec/bin/wazuh-logtest` on the manager.

## 7. AI report (optional)

Stage 5 writes an incident report for every quarantined email. Pick one backend in `~/analyzer/secrets.env`;
with none, a template report is written instead.

| Backend | Setting | Notes |
|---|---|---|
| Claude Code CLI | `AI_BACKEND=claude-code`, optional `CLAUDE_CODE_MODEL=sonnet` | Uses a Claude Pro or Max plan. Install with `curl -fsSL https://claude.ai/install.sh \| bash`, then run `claude` once to log in. The analyzer runs it with every tool turned off. |
| Claude API | `ANTHROPIC_API_KEY=...`, optional `AI_REPORT_MODEL` | Pay per use; a report costs a few cents. |
| Ollama (local, free) | `AI_BACKEND=ollama`, optional `OLLAMA_MODEL` | `curl -fsSL https://ollama.com/install.sh \| sh`, then `ollama pull qwen2.5:3b` (needs about 4 GB free RAM). Nothing leaves the VM. |

A Claude login on the analyzer VM sits next to live malware. Log out (`claude`, then `/logout`) when you're not
using the lab.

## 8. YARA (optional)

If `yara-python` is installed, the analyzer scans every file with the rules in `~/analyzer/yara/` before
VirusTotal. Any match raises the file's verdict to at least suspicious.

```bash
pip install yara-python
mkdir -p ~/analyzer/yara && cd ~/analyzer/yara
wget https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip
unzip yara-forge-rules-core.zip && mv packages/core/yara-rules-core.yar . && rm -rf packages *.zip
```

Every `.yar` and `.yara` file in that folder is loaded, so custom rules go in the same place.

## 9. First run

```bash
cd ~/analyzer
set -a; source secrets.env; set +a
python3 new_analyzer.py --eml /path/to/Phish-Analyzer/samples/phish_sample.eml   # offline test, Gmail untouched
python3 new_analyzer.py                                                          # check the inbox for new mail
```

Use a terminal at least 104 columns wide. The sample emails use reserved `.example` domains and contain no
payload, so they exercise the triage stage only.
