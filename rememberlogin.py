import streamlit as st
from typing import List, Optional
import random, time
from datetime import datetime, date, timedelta, timezone
import base64, hmac, hashlib, json
import extra_streamlit_components as stx

#Remember login
AUTH_SECRET = st.secrets.get("auth_secret", "dev-secret-change-me").encode("utf-8")
REMEMBER_DAYS = int(st.secrets.get("remember_days", 30))
COOKIE_NAME = st.secrets.get("cookie_name", "pullups_auth")
COOKIE_KEY = st.secrets.get("cookie_key", "pullups_cookie_namespace")  # namespace for the component

_COOKIE_MGR = None  # <-- global singleton

# --- Token helpers (HMAC-signeret payload) ---
def _b64u(x: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(x).decode().rstrip("=")

def _b64u_dec(s: str) -> bytes:
    import base64
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode())

def _now_ts() -> int:
    return int(time.time())

def _sign(payload: dict) -> str:
    msg = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(AUTH_SECRET, msg, hashlib.sha256).digest()
    return _b64u(msg) + "." + _b64u(sig)

def _verify(token: str) -> Optional[dict]:
    try:
        msg_b64, sig_b64 = token.split(".", 1)
        msg = _b64u_dec(msg_b64)
        expected = hmac.new(AUTH_SECRET, msg, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64u_dec(sig_b64)):
            return None
        payload = json.loads(msg.decode())
        if int(payload.get("exp", 0)) < _now_ts():
            return None
        return payload
    except Exception:
        return None

def _issue_token(username: str, days: int = REMEMBER_DAYS) -> str:
    payload = {"u": username, "exp": _now_ts() + days * 24 * 3600, "v": 1}
    return _sign(payload)

# --- Cookie manager (top-level cookies, delt på tværs af faner) ---
def _get_cookie_mgr():
    global _COOKIE_MGR
    if _COOKIE_MGR is None:
        # Opret KUN én CookieManager med stabil key
        _COOKIE_MGR = stx.CookieManager(key=COOKIE_KEY)
    return _COOKIE_MGR

def _set_cookie(token: str | None):
    cm = _get_cookie_mgr()
    if token:
        expires = datetime.now(timezone.utc) + timedelta(days=REMEMBER_DAYS)
        cm.set(COOKIE_NAME, token, expires_at=expires, same_site="Lax")
    else:
        cm.delete(COOKIE_NAME)

def _get_cookie() -> str | None:
    cm = _get_cookie_mgr()
    v = cm.get(COOKIE_NAME)
    if isinstance(v, dict):  # kompatibilitet på tværs af versioner
        return v.get(COOKIE_NAME)
    return v