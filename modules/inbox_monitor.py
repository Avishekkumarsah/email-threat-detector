"""
inbox_monitor.py
-----------------
Multi-tenant real-time inbox monitoring over IMAP.

Instead of polling a single hardwired account from .env, this version
fetches ALL active IMAP credentials from the database each cycle, then
processes each account's unseen emails.

The callback signature is:  on_new_email(raw_bytes, user_id)

Error handling is per-account - one bad password can't kill the entire loop,
and errors are stored per user so one user never sees another user's errors.
"""

import imaplib
import socket
import ssl
import threading
import traceback
from datetime import datetime

import config


class RobustIMAP4_SSL(imaplib.IMAP4_SSL):
    """
    Subclass of imaplib.IMAP4_SSL that enforces IPv4 (socket.AF_INET) resolution.
    This prevents '[Errno 101] Network is unreachable' errors caused by broken/missing
    IPv6 routing in Linux container / cloud hosting environments (Docker, Render, AWS).
    """
    def _create_socket(self, timeout=None):
        try:
            addr_info = socket.getaddrinfo(self.host, self.port, socket.AF_INET, socket.SOCK_STREAM)
            if addr_info:
                ip_addr = addr_info[0][4][0]
                server_hostname = self.host if ssl.HAS_SNI else None
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if timeout is not None and timeout != socket._GLOBAL_DEFAULT_TIMEOUT:
                    raw_sock.settimeout(timeout)
                raw_sock.connect((ip_addr, self.port))
                return self.ssl_context.wrap_socket(raw_sock, server_hostname=server_hostname)
        except Exception:
            pass
        return super()._create_socket(timeout)


# -- Shared state --------------------------------------------------------------
_state = {
    "running": False,
    "last_check": None,
    "emails_scanned": 0,
    "active_accounts": 0,
    "recent": [],          # newest first, max 20 entries (each tagged with user_id)
    "errors": {},          # {user_id: "error message"}
}
_stop_event = threading.Event()
_thread = None
_lock = threading.Lock()


def get_status(user_id=None) -> dict:
    """
    Thread-safe snapshot of monitoring state.
    If user_id is given, only that user's feed and error are returned.
    """
    with _lock:
        snap = dict(_state)
        errors = _state["errors"]
        snap["recent"] = [
            e for e in _state["recent"]
            if user_id is None or e.get("user_id") == user_id
        ]
        if user_id is not None:
            snap["last_error"] = errors.get(user_id)
        else:
            snap["last_error"] = next(iter(errors.values()), None)
        snap.pop("errors", None)
        return snap


# -- Login test (used by Settings before saving) -------------------------------
def test_login(host: str, port, email: str, password: str):
    """Try a real IMAP login. Returns (ok: bool, error_message: str | None)."""
    try:
        conn = RobustIMAP4_SSL(host, int(port), timeout=15)
        try:
            conn.login(email, password)
        finally:
            try:
                conn.logout()
            except Exception:
                pass
        return True, None
    except imaplib.IMAP4.error:
        return False, (
            "The mail server rejected these credentials. "
            "Use a 16-character App Password, not your normal password."
        )
    except Exception as e:
        err_str = str(e)
        if "101" in err_str or "unreachable" in err_str.lower():
            return False, (
                f"Could not reach mail server ({host}:{port}). "
                "Network is unreachable. If deploying to cloud hosting (e.g. Render/Vercel/Railway), "
                "ensure outbound TCP port 993 is permitted by your host."
            )
        return False, f"Could not reach the mail server: {e}"


# -- Per-account IMAP helpers --------------------------------------------------
def _connect_imap(host: str, port: int, email: str, password: str):
    conn = RobustIMAP4_SSL(host, port, timeout=30)
    conn.login(email, password)
    conn.select("INBOX")
    return conn


def _fetch_unseen_raw_emails(conn):
    status, data = conn.search(None, "UNSEEN")
    if status != "OK" or not data or not data[0]:
        return []
    raw_emails = []
    for msg_id in data[0].split():
        st, msg_data = conn.fetch(msg_id, "(RFC822)")
        if st == "OK" and msg_data and msg_data[0]:
            raw_emails.append(msg_data[0][1])
    return raw_emails


def _set_error(user_id, message):
    with _lock:
        _state["errors"][user_id] = message


def _process_account(cred: dict, on_new_email, interval_seconds: int):
    """
    Poll one user's inbox. All errors are caught and reported per-account
    so a single bad credential never kills the entire monitoring loop.
    """
    from modules import database  # local import avoids circular deps at module load

    user_id = cred["user_id"]
    host = cred["imap_host"]
    port = int(cred["imap_port"])
    email = cred["imap_email"]

    # Clear any old error for this user; a new one is set below if it fails again
    with _lock:
        _state["errors"].pop(user_id, None)

    try:
        password = database.decrypt_password(cred["encrypted_pass"])
    except Exception as e:
        _set_error(user_id, f"Cannot decrypt IMAP password - {e}. "
                            f"Re-save your IMAP settings.")
        return

    try:
        conn = _connect_imap(host, port, email, password)
        raw_emails = _fetch_unseen_raw_emails(conn)
        try:
            conn.logout()
        except Exception:
            pass

        for raw_bytes in raw_emails:
            try:
                on_new_email(raw_bytes, user_id)
                with _lock:
                    _state["emails_scanned"] += 1
            except Exception as e:
                _set_error(user_id, f"Failed to process email - {e}")

    except imaplib.IMAP4.error as e:
        _set_error(user_id, f"IMAP auth/connection failed - {e}. "
                            f"Check your App Password in Settings.")
    except Exception as e:
        _set_error(user_id, f"Unexpected error - {e}")
        traceback.print_exc()


# -- Main poll loop ------------------------------------------------------------
def _poll_loop(on_new_email, interval_seconds: int):
    """Runs in a background daemon thread until stop_monitoring() is called."""
    from modules import database

    while not _stop_event.is_set():
        try:
            active_creds = database.get_all_active_imap_credentials()
            with _lock:
                _state["active_accounts"] = len(active_creds)
                _state["last_check"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            for cred in active_creds:
                if _stop_event.is_set():
                    break
                _process_account(cred, on_new_email, interval_seconds)

        except Exception as e:
            _set_error("poll", f"Poll loop error: {e}")
            traceback.print_exc()

        _stop_event.wait(interval_seconds)


# -- Multi-worker Process Lock Guard -----------------------------------------
_monitor_socket = None

def _acquire_worker_lock() -> bool:
    """
    In multi-worker environments (e.g. Gunicorn -w 4), ensures background thread runs cleanly.
    Uses socket reuse flags and safe fallback to guarantee thread startup across OS environments.
    """
    global _monitor_socket
    if _monitor_socket is not None:
        return True
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 47829))
        _monitor_socket = s
        return True
    except Exception:
        # Fallback gracefully so monitoring runs in single-worker / desktop environments
        return True


# -- Public API ----------------------------------------------------------------
def start_monitoring(on_new_email, interval_seconds: int = None) -> bool:
    """
    Start the background monitoring thread.
    on_new_email(raw_bytes: bytes, user_id: int) is called for each new email.
    Returns False if already running and active.
    """
    global _thread
    with _lock:
        if _state["running"] and _thread is not None and _thread.is_alive():
            return False

    _acquire_worker_lock()

    interval = interval_seconds or config.POLL_INTERVAL_SECONDS
    _stop_event.clear()
    _thread = threading.Thread(
        target=_poll_loop,
        args=(on_new_email, interval),
        daemon=True,
    )
    _thread.start()
    with _lock:
        _state["running"] = True
    return True


def poll_now(on_new_email) -> bool:
    """Trigger an immediate inbox check in a background thread."""
    t = threading.Thread(
        target=_poll_loop_once,
        args=(on_new_email,),
        daemon=True,
    )
    t.start()
    return True


def _poll_loop_once(on_new_email):
    from modules import database
    try:
        active_creds = database.get_all_active_imap_credentials()
        with _lock:
            _state["active_accounts"] = len(active_creds)
            _state["last_check"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for cred in active_creds:
            _process_account(cred, on_new_email, config.POLL_INTERVAL_SECONDS)
    except Exception as e:
        _set_error("poll", f"Poll error: {e}")


def stop_monitoring() -> bool:
    """Stop the background thread gracefully."""
    with _lock:
        if not _state["running"]:
            return False
    _stop_event.set()
    with _lock:
        _state["running"] = False
    return True


def record_scan(subject: str, sender: str, verdict: str, scan_id: int, user_id: int = None):
    """Called by app.py after each auto-scan to update the live dashboard feed."""
    with _lock:
        _state["recent"].insert(0, {
            "time":    datetime.now().strftime("%H:%M:%S"),
            "subject": subject or "(no subject)",
            "from":    sender or "(unknown sender)",
            "verdict": verdict,
            "scan_id": scan_id,
            "user_id": user_id,
        })
        _state["recent"] = _state["recent"][:20]