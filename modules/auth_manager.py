# auth_manager.py
import msal
import os

CLIENT_ID = 'de48fb58-ae35-457a-99cc-15d6c1493ca1'
CLIENT_SECRET = '78681cc2-c62c-482b-a863-86d1d2bf82f4'
AUTHORITY_URL = 'https://login.microsoftonline.com/common'
REDIRECT_URI = 'http://localhost:5000/callback'
SCOPE = ["https://outlook.office.com/IMAP.AccessAsUser.All"]
TOKEN_CACHE_FILE = 'token_cache.json'

def load_cache():
    """Load token cache from a file."""
    cache = msal.SerializableTokenCache()
    if os.path.exists(TOKEN_CACHE_FILE):
        with open(TOKEN_CACHE_FILE, 'r') as f:
            cache.deserialize(f.read())
    return cache

def save_cache(cache):
    """Save token cache to a file."""
    if cache.has_state_changed:
        with open(TOKEN_CACHE_FILE, 'w') as f:
            f.write(cache.serialize())

token_cache = load_cache()

# MSAL Client Application
msal_app = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY_URL,  token_cache=token_cache)

def get_oauth2_token():
    """Fetch OAuth2 token using MSAL, with caching."""
    accounts = msal_app.get_accounts()
    if accounts:
        # Try to acquire token silently from cache
        token_result = msal_app.acquire_token_silent(SCOPE, account=accounts[0])
    else:
        token_result = None
    
    if not token_result:
        # If no cached token, do interactive login
        token_result = msal_app.acquire_token_interactive(scopes=SCOPE)
    
    # Save cache if it has changed
    save_cache(msal_app.token_cache)

    if "access_token" in token_result:
        return token_result["access_token"]
    else:
        raise Exception("Could not obtain access token")
