"""
auth_remote.py - Gmail sign-in when the account's owner is on another machine.

1. Run this on the analyzer VM. It writes the sign-in link to login_url.txt.
2. Send that link to the person who can log in to the Gmail account.
3. They open it, sign in, click Continue and Allow. Their browser then shows a
   broken http://localhost:8080/... page. They copy that whole address and send it back.
4. Paste it here. token.json is saved; the password never leaves their machine.

    python3 auth_remote.py
"""
import os

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"   # the redirect is plain http://localhost; nothing is served
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"    # don't fail if Google lists the scope slightly differently
from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = ["https://mail.google.com/"]
HERE = os.path.dirname(os.path.abspath(__file__))
CLIENT_SECRET = os.path.join(HERE, "client_secret.json")
TOKEN_FILE = os.path.join(HERE, "token.json")
URL_FILE = os.path.join(HERE, "login_url.txt")

flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET, SCOPES, redirect_uri="http://localhost:8080/")
url, _ = flow.authorization_url(prompt="consent", access_type="offline")
with open(URL_FILE, "w") as f:
    f.write(url + "\n")

print(f"\nSign-in link saved to {URL_FILE} (one line, {len(url)} characters).")
print("Send the whole link to the account owner. After they click Allow, their browser")
print("lands on a page that won't load (http://localhost:8080/?...). That's expected.\n")
answer = input("Paste the full address from their address bar, then press Enter:\n> ").strip()

flow.fetch_token(authorization_response=answer)
token_json = flow.credentials.to_json()
with open(TOKEN_FILE, "w") as f:
    f.write(token_json)
os.chmod(TOKEN_FILE, 0o600)
os.remove(URL_FILE)
print(f"Saved {TOKEN_FILE}")
