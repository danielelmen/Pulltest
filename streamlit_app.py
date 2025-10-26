import base64, hmac, hashlib, json
from urllib.parse import urlencode
import streamlit as st
from streamlit.components.v1 import html
import time

USERS = st.secrets.get("users", {})
AUTH_SECRET = st.secrets.get("auth_secret", "dev-secret-change-me").encode("utf-8")
REMEMBER_DAYS = int(st.secrets.get("remember_days", 30))
TOKEN_QUERY_KEY = "token"
LS_KEY = "pullups_auth"  # localStorage key

def _b64u(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode().rstrip("=")

def _b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode())

def _now_ts() -> int:
    return int(time.time())

def _sign(payload: dict) -> str:
    msg = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(AUTH_SECRET, msg, hashlib.sha256).digest()
    return _b64u(msg) + "." + _b64u(sig)

def _verify(token: str) -> dict | None:
    try:
        msg_b64, sig_b64 = token.split(".", 1)
        msg = _b64u_dec(msg_b64)
        expected = hmac.new(AUTH_SECRET, msg, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64u_dec(sig_b64)):
            return None
        payload = json.loads(msg.decode())
        # Expiry check
        if int(payload.get("exp", 0)) < _now_ts():
            return None
        return payload
    except Exception:
        return None

def _issue_token(username: str, days: int = REMEMBER_DAYS) -> str:
    payload = {
        "u": username,
        "exp": _now_ts() + days * 24 * 3600,
        "v": 1
    }
    return _sign(payload)

def _set_localstorage(token: str | None):
    """Skriv/slet token i localStorage fra Python via en lille HTML/JS-blob."""
    if token:
        js = f"""
        <script>
        try {{
          localStorage.setItem("{LS_KEY}", {json.dumps(token)});
        }} catch (e) {{}}
        </script>
        """
    else:
        js = f"""
        <script>
        try {{
          localStorage.removeItem("{LS_KEY}");
          // Fjern ?token fra URL og reload
          const url = new URL(window.location.href);
          url.searchParams.delete("{TOKEN_QUERY_KEY}");
          window.location.replace(url.toString());
        }} catch (e) {{}}
        </script>
        """
    html(js, height=0)

def _bootstrap_query_from_localstorage():
    """Hvis URL ingen ?token har, men localStorage har => tilføj og reload."""
    js = f"""
    <script>
    (function(){{
      try {{
        const key = "{LS_KEY}";
        const qk  = "{TOKEN_QUERY_KEY}";
        const url = new URL(window.location.href);
        const has = url.searchParams.get(qk);
        const local = window.localStorage.getItem(key);
        if (!has && local) {{
          url.searchParams.set(qk, local);
          // hard reload så Streamlit fanger query param
          window.location.replace(url.toString());
        }}
      }} catch (e) {{}}
    }})();
    </script>
    """
    html(js, height=0)

def _read_token_from_query() -> str | None:
    q = st.experimental_get_query_params()
    v = q.get(TOKEN_QUERY_KEY, [None])[0]
    return v or None

def authenticate():
    # init session flags
    st.session_state.setdefault("authenticated", False)
    st.session_state.setdefault("username", "")

    # 1) Hvis allerede logget ind i denne session, returnér
    if st.session_state["authenticated"]:
        return

    # 2) Bootstrapping: hent token fra localStorage -> URL ?token=...
    _bootstrap_query_from_localstorage()

    # 3) Prøv auto-login via ?token=
    token = _read_token_from_query()
    if token:
        payload = _verify(token)
        if payload and (u := payload.get("u")) in USERS:
            st.session_state["authenticated"] = True
            st.session_state["username"] = u
            # (valgfrit) bump udløb ved hvert besøg:
            fresh = _issue_token(u)
            st.experimental_set_query_params(**{TOKEN_QUERY_KEY: fresh})
            _set_localstorage(fresh)
            return  # vi er nu logget ind

    # 4) Ingen gyldig token -> vis login form
    st.title("Log ind")
    username = st.text_input("Brugernavn")
    password = st.text_input("Adgangskode", type="password")
    remember = st.checkbox("Forbliv logget ind på denne enhed", value=True)

    if st.button("Login"):
        if username in USERS and USERS[username] == password:
            st.session_state["authenticated"] = True
            st.session_state["username"] = username

            if remember:
                t = _issue_token(username)
                # læg token i URL (så genbesøg virker uden JS) og i localStorage
                st.experimental_set_query_params(**{TOKEN_QUERY_KEY: t})
                _set_localstorage(t)
            else:
                # hvis der tidligere lå et token i URL eller localStorage, fjern dem
                st.experimental_set_query_params()
                _set_localstorage(None)
            st.rerun()
        else:
            st.error("Forkert brugernavn eller adgangskode")

    st.stop()  # stop appen hvis ikke logget ind

def perform_logout():
    """Kald denne fra din Log ud-knap i sidebar."""
    st.session_state["authenticated"] = False
    st.session_state["username"] = ""
    # Ryd token begge steder
    st.experimental_set_query_params()
    _set_localstorage(None)
    st.rerun()


authenticate()
user = st.session_state["username"]

st.caption("Yay!")

# i din sidebar logout-knap (erstat tidligere logout):
with st.sidebar:
    if st.session_state.get("authenticated"):
        if st.button("Log ud", use_container_width=True):
            perform_logout()
