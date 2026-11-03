"""
auth_setup.py - one-time Gmail sign-in for the analyzer.

Opens a browser, you log into the Gmail account the analyzer will watch and
click Allow, and the result is saved to token.json (the refresh token).
Run it again whenever the analyzer logs auth_failed.

    python3 auth_setup.py
"""
import os
from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = ["https://mail.google.com/"]          # the only scope Gmail accepts for IMAP
HERE = os.path.dirname(os.path.abspath(__file__))
CLIENT_SECRET = os.path.join(HERE, "client_secret.json")
TOKEN_FILE = os.path.join(HERE, "token.json")

flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET, SCOPES)
# prompt="consent" makes Google always hand back a refresh token, even on a re-run.
creds = flow.run_local_server(port=0, prompt="consent")

with open(TOKEN_FILE, "w") as f:
    f.write(creds.to_json())
os.chmod(TOKEN_FILE, 0o600)                     # token.json is now the secret: owner read/write only
print(f"Saved {TOKEN_FILE}")
