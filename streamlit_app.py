import base64, hmac, hashlib, json, time
from datetime import datetime, timedelta, timezone
from typing import Optional
import streamlit as st
import extra_streamlit_components as stx  # NEW


# --- Settings / secrets ---
USERS = st.secrets.get("users", {})
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



# --- Public API ---
def authenticate():
    # Sørg for at komponenten er oprettet én gang i dette run
    _ = _get_cookie_mgr()

    st.session_state.setdefault("authenticated", False)
    st.session_state.setdefault("username", "")

    # 1) Session already authed
    if st.session_state["authenticated"]:
        return

    # 2) Prøv auto-login via cookie
    token = _get_cookie()
    if token:
        payload = _verify(token)
        if payload and (u := payload.get("u")) in USERS:
            st.session_state["authenticated"] = True
            st.session_state["username"] = u
            # valgfrit: “rolling” fornyelse
            fresh = _issue_token(u)
            _set_cookie(fresh)
            return

    # 3) Ingen gyldig cookie -> vis login-form
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
                _set_cookie(t)  # skriv cookie i browseren

                # VIGTIGT: giv browseren et øjeblik til at skrive cookien,
                # reload i TOP-vinduet, og stop Python-runnet nu.
                st.success("Logget ind – husker dit login på denne enhed.")
                st.markdown(
                    """
                    <script>
                    setTimeout(function(){
                    try { window.top.location.reload(); }
                    catch(e){ window.location.reload(); }
                    }, 150);
                    </script>
                    """,
                    unsafe_allow_html=True
                )
                st.stop()
            else:
                _set_cookie(None)
                st.rerun()
        else:
            st.error("Forkert brugernavn eller adgangskode")

    st.stop()  # stop resten af appen når ikke logget ind

def perform_logout():
    # Sørg for at komponenten er instansieret i dette run
    _ = _get_cookie_mgr()

    # 1) Nulstil session
    st.session_state["authenticated"] = False
    st.session_state["username"] = ""

    # 2) Slet via komponent (hurtigst muligt)
    try:
        _get_cookie_mgr().delete(COOKIE_NAME)
    except Exception:
        pass

    # 3) JS: slet ALLE varianter (med/uden Domain, flere paths), og reload TOP-vinduet
    st.markdown(
        f"""
        <script>
        (function(){{
          try {{
            const name = {json.dumps(COOKIE_NAME)};
            const past = "Thu, 01 Jan 1970 00:00:00 GMT";
            const proto = window.location.protocol;
            const host  = window.location.hostname;
            const paths = ["/", (window.location.pathname.split("/").slice(0,2).join("/") || "/")];
            const domains = [undefined, host, "." + host];

            function delCookie(path, domain) {{
              let parts = [name + "=; Expires=" + past, "Path=" + path, "SameSite=Lax"];
              if (domain) parts.push("Domain=" + domain);
              // Secure-flag behøves ikke for sletning, men skader ikke på https
              if (proto === "https:") parts.push("Secure");
              document.cookie = parts.join("; ");
            }}

            for (const p of paths) {{
              // uden Domain
              delCookie(p, undefined);
              // med host og .host
              for (const d of [host, "."+host]) delCookie(p, d);
            }}

            // Fjern også evt. ?token fra ældre implementationer
            try {{
              const url = new URL(window.top.location.href);
              url.searchParams.delete("token");
              // Reload top-vinduet EFTER sletning
              setTimeout(() => {{
                window.top.location.replace(url.toString());
              }}, 50);
            }} catch(e) {{
              // fallback hard reload
              setTimeout(() => window.top.location.reload(), 50);
            }}
          }} catch(e) {{}}
        }})();
        </script>
        """,
        unsafe_allow_html=True
    )

    # 4) Stop run her – lad browseren reloade (vi undgår at læse en evt. “gammel” cookie i samme run)
    st.stop()





authenticate()
user = st.session_state["username"]

st.caption("Yay!")

# i din sidebar logout-knap (erstat tidligere logout):
with st.sidebar:
    if st.session_state.get("authenticated"):
        if st.button("Log ud", use_container_width=True):
            perform_logout()
