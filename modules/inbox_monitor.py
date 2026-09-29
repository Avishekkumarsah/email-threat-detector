"""
inbox_monitor.py
-----------------
Multi-tenant real-time inbox monitoring over IMAP.

Architecture (v2 — per-user threads)
-------------------------------------
Each user with active IMAP credentials gets their OWN background thread.
Starting / stopping one user's monitor has zero effect on others.

State is stored per-user in _user_state[user_id]:
  {
    "running":        bool,
    "last_check":     str | None,
    "emails_scanned": int,
    "recent":         list[dict],   # newest-first, max 50 per user
    "last_error":     str | None,
  }

Public API
----------
  start_monitoring(on_new_email)           → start threads for ALL active IMAP users
  start_monitoring_user(user_id, …)        → start/restart ONE user's thread
  stop_monitoring()                        → stop ALL threads (admin/server shutdown)
  stop_monitoring_user(user_id)            → stop only ONE user's thread
  poll_now(on_new_email, user_id=None)     → one-shot poll (one user or all)
  get_status(user_id=None)                 → status for one user (or global summary)
  record_scan(subject, sender, verdict, …) → update live feed after auto-scan
  test_login(host, port, email, password)  → validate IMAP credentials

Callback signature: on_new_email(raw_bytes: bytes, user_id: int)
"""

import imaplib
import socket
import ssl
import threading
import traceback
from datetime import datetime

import config


# ── IPv4-forced IMAP SSL ──────────────────────────────────────────────────────

class RobustIMAP4_SSL(imaplib.IMAP4_SSL):
    """
    Forces IPv4 resolution to avoid '[Errno 101] Network is unreachable'
    in cloud / Docker environments with broken IPv6 routing.
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


# ── Per-user state ────────────────────────────────────────────────────────────

_lock         = threading.Lock()
_user_threads = {}      # {user_id: threading.Thread}
_user_stop    = {}      # {user_id: threading.Event}
_user_state   = {}      # {user_id: dict}


def _default_state() -> dict:
    return {
        "running":        False,
        "last_check":     None,
        "emails_scanned": 0,
        "recent":         [],
        "last_error":     None,
    }


def _ensure_state(user_id: int):
    """Initialise state for user_id if it doesn't exist yet."""
    if user_id not in _user_state:
        _user_state[user_id] = _default_state()


# ── Public status API ─────────────────────────────────────────────────────────

def get_status(user_id: int = None) -> dict:
    """
    Thread-safe snapshot.
    • user_id given → returns that user's state dict.
    • user_id=None  → returns global summary (admin use).
    """
    with _lock:
        if user_id is not None:
            _ensure_state(user_id)
            return dict(_user_state[user_id])

        # Global summary
        all_running   = [uid for uid, s in _user_state.items() if s["running"]]
        total_scanned = sum(s["emails_scanned"] for s in _user_state.values())
        return {
            "running":         len(all_running) > 0,
            "active_accounts": len(all_running),
            "emails_scanned":  total_scanned,
            "last_check":      max(
                (s["last_check"] for s in _user_state.values() if s["last_check"]),
                default=None,
            ),
            "last_error":      next(
                (s["last_error"] for s in _user_state.values() if s["last_error"]),
                None,
            ),
            "recent": sorted(
                [e for s in _user_state.values() for e in s["recent"]],
                key=lambda e: e.get("time", ""),
                reverse=True,
            )[:20],
        }


def get_all_user_statuses() -> dict:
    """Return {user_id: state_dict} for all known users (admin dashboard)."""
    with _lock:
        return {uid: dict(s) for uid, s in _user_state.items()}


# ── IMAP helpers ──────────────────────────────────────────────────────────────

def test_login(host: str, port, email: str, password: str):
    """Validate credentials with a real IMAP connection. Returns (ok, error_msg)."""
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
                "Network is unreachable. Ensure outbound TCP port 993 is permitted by your host."
            )
        return False, f"Could not reach the mail server: {e}"


def _connect_imap(host: str, port: int, email: str, password: str):
    conn = RobustIMAP4_SSL(host, port, timeout=30)
    conn.login(email, password)
    conn.select("INBOX")
    return conn


def _fetch_unseen_raw_emails(conn) -> list[bytes]:
    status, data = conn.search(None, "UNSEEN")
    if status != "OK" or not data or not data[0]:
        return []
    raw_emails = []
    for msg_id in data[0].split():
        st, msg_data = conn.fetch(msg_id, "(RFC822)")
        if st == "OK" and msg_data and msg_data[0]:
            raw_emails.append(msg_data[0][1])
    return raw_emails


# ── Per-user poll loop ────────────────────────────────────────────────────────

def _user_poll_loop(user_id: int, on_new_email, interval: int):
    """
    Background thread for ONE user.
    Runs until the user's stop event is set or the user deactivates IMAP.
    """
    from modules import database

    stop_event = _user_stop.get(user_id)
    if stop_event is None:
        return

    while not stop_event.is_set():
        try:
            cred = database.get_imap_credentials(user_id)
            if not cred or not cred.get("is_active"):
                # User deactivated — stop naturally
                break

            _poll_one_account(cred, on_new_email, user_id)

        except Exception as e:
            _set_error(user_id, f"Poll loop error: {e}")
            traceback.print_exc()

        stop_event.wait(interval)

    # Mark as stopped when thread exits
    with _lock:
        if user_id in _user_state:
            _user_state[user_id]["running"] = False


def _poll_one_account(cred: dict, on_new_email, user_id: int):
    """Poll a single IMAP account and process any unseen emails."""
    from modules import database

    host  = cred["imap_host"]
    port  = int(cred["imap_port"])
    email = cred["imap_email"]

    # Clear previous error
    with _lock:
        _ensure_state(user_id)
        _user_state[user_id]["last_error"] = None
        _user_state[user_id]["last_check"]  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        password = database.decrypt_password(cred["encrypted_pass"])
    except Exception as e:
        _set_error(user_id, f"Cannot decrypt IMAP password — {e}. Re-save your IMAP settings.")
        return

    try:
        imap_conn = _connect_imap(host, port, email, password)
        raw_emails = _fetch_unseen_raw_emails(imap_conn)
        try:
            imap_conn.logout()
        except Exception:
            pass

        for raw_bytes in raw_emails:
            try:
                on_new_email(raw_bytes, user_id)
                with _lock:
                    _user_state[user_id]["emails_scanned"] += 1
            except Exception as e:
                _set_error(user_id, f"Failed to process email — {e}")

    except imaplib.IMAP4.error as e:
        _set_error(user_id, f"IMAP auth failed — {e}. Check your App Password in Settings.")
    except Exception as e:
        _set_error(user_id, f"Unexpected error — {e}")
        traceback.print_exc()


def _set_error(user_id: int, message: str):
    with _lock:
        _ensure_state(user_id)
        _user_state[user_id]["last_error"] = message


# ── Watchdog ──────────────────────────────────────────────────────────────────

_watchdog_thread = None
_watchdog_stop   = threading.Event()
_on_new_email_ref = None   # stored so watchdog can restart dead threads


def _watchdog_loop():
    """Restarts any per-user thread that has silently died."""
    from modules import database

    while not _watchdog_stop.is_set():
        _watchdog_stop.wait(60)   # check every 60 s
        if _watchdog_stop.is_set():
            break
        if _on_new_email_ref is None:
            continue
        try:
            with _lock:
                dead_users = [
                    uid for uid, t in _user_threads.items()
                    if _user_state.get(uid, {}).get("running") and (t is None or not t.is_alive())
                ]
            for uid in dead_users:
                _restart_user_thread(uid, _on_new_email_ref)
        except Exception:
            traceback.print_exc()


def _start_watchdog(on_new_email):
    global _watchdog_thread, _on_new_email_ref
    _on_new_email_ref = on_new_email
    if _watchdog_thread is None or not _watchdog_thread.is_alive():
        _watchdog_stop.clear()
        _watchdog_thread = threading.Thread(target=_watchdog_loop, daemon=True, name="monitor-watchdog")
        _watchdog_thread.start()


def _restart_user_thread(user_id: int, on_new_email):
    """Restart a dead thread for user_id (called by watchdog, already under lock context)."""
    interval = config.POLL_INTERVAL_SECONDS
    stop_evt = threading.Event()
    _user_stop[user_id] = stop_evt
    t = threading.Thread(
        target=_user_poll_loop,
        args=(user_id, on_new_email, interval),
        daemon=True,
        name=f"monitor-user-{user_id}",
    )
    t.start()
    with _lock:
        _user_threads[user_id] = t
        _ensure_state(user_id)
        _user_state[user_id]["running"] = True


# ── Public API ────────────────────────────────────────────────────────────────

def start_monitoring_user(user_id: int, on_new_email, interval: int = None) -> bool:
    """
    Start (or restart) the background thread for one user.
    Returns True if a new thread was started, False if already running fine.
    """
    interval = interval or config.POLL_INTERVAL_SECONDS

    with _lock:
        existing_thread = _user_threads.get(user_id)
        if existing_thread is not None and existing_thread.is_alive():
            # Already running — nothing to do
            return False

    # Stop any stale stop-event
    old_stop = _user_stop.get(user_id)
    if old_stop:
        old_stop.set()

    stop_evt = threading.Event()
    _user_stop[user_id] = stop_evt

    t = threading.Thread(
        target=_user_poll_loop,
        args=(user_id, on_new_email, interval),
        daemon=True,
        name=f"monitor-user-{user_id}",
    )
    t.start()

    with _lock:
        _user_threads[user_id] = t
        _ensure_state(user_id)
        _user_state[user_id]["running"] = True
        _user_state[user_id]["last_error"] = None

    _start_watchdog(on_new_email)
    return True


def stop_monitoring_user(user_id: int) -> bool:
    """
    Stop only ONE user's monitoring thread. Other users are unaffected.
    Returns True if a thread was stopped, False if wasn't running.
    """
    stop_evt = _user_stop.get(user_id)
    if stop_evt:
        stop_evt.set()

    with _lock:
        _ensure_state(user_id)
        was_running = _user_state[user_id]["running"]
        _user_state[user_id]["running"] = False

    return was_running


def start_monitoring(on_new_email, interval: int = None) -> bool:
    """
    Start threads for ALL users with active IMAP credentials.
    Called at app startup and after bulk enable operations.
    Returns True if at least one thread was started.
    """
    from modules import database
    interval = interval or config.POLL_INTERVAL_SECONDS

    active_creds = database.get_all_active_imap_credentials()
    started_any = False
    for cred in active_creds:
        uid = cred["user_id"]
        started = start_monitoring_user(uid, on_new_email, interval)
        if started:
            started_any = True

    _start_watchdog(on_new_email)
    return started_any


def stop_monitoring() -> bool:
    """
    Stop ALL monitoring threads (admin action / server shutdown).
    Returns True always.
    """
    global _watchdog_thread

    # Stop watchdog first
    _watchdog_stop.set()

    with _lock:
        user_ids = list(_user_stop.keys())

    for uid in user_ids:
        stop_monitoring_user(uid)

    return True


def poll_now(on_new_email, user_id: int = None) -> bool:
    """
    Trigger an immediate one-shot poll in a background thread.
    user_id=None → poll all active accounts.
    """
    t = threading.Thread(
        target=_poll_now_worker,
        args=(on_new_email, user_id),
        daemon=True,
    )
    t.start()
    return True


def _poll_now_worker(on_new_email, user_id: int = None):
    from modules import database
    try:
        if user_id is not None:
            cred = database.get_imap_credentials(user_id)
            if cred:
                _poll_one_account(cred, on_new_email, user_id)
        else:
            for cred in database.get_all_active_imap_credentials():
                _poll_one_account(cred, on_new_email, cred["user_id"])
    except Exception as e:
        traceback.print_exc()


def record_scan(subject: str, sender: str, verdict: str, scan_id: int, user_id: int = None):
    """Called by app.py after each auto-scan to update the live feed."""
    with _lock:
        if user_id is not None:
            _ensure_state(user_id)
            _user_state[user_id]["recent"].insert(0, {
                "time":    datetime.now().strftime("%H:%M:%S"),
                "subject": subject or "(no subject)",
                "from":    sender  or "(unknown sender)",
                "verdict": verdict,
                "scan_id": scan_id,
                "user_id": user_id,
            })
            _user_state[user_id]["recent"] = _user_state[user_id]["recent"][:50]