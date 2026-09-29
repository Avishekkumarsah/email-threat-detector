"""
app.py
------
Flask routes for the multi-tenant Email Threat Detector SaaS platform.

All analysis routes are protected with @login_required so each user only
ever sees their own scans.  IMAP credentials are managed via /settings.
"""

import os
import uuid

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, send_file, jsonify,
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user,
)

import config
from modules import (
    parser, content_analysis, header_analysis, url_analysis,
    attachment_analysis, geolocation, scoring, database, report, inbox_monitor,
)
from modules.auth import User, register_user, verify_user, load_user

from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
import secrets
from datetime import datetime, timedelta

# -- App setup -----------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"]          = config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"]  = config.MAX_UPLOAD_MB * 1024 * 1024
app.config["WTF_CSRF_TIME_LIMIT"] = config.WTF_CSRF_TIME_LIMIT

# Flask-Mail configuration
app.config["MAIL_SERVER"]         = config.MAIL_SERVER
app.config["MAIL_PORT"]           = config.MAIL_PORT
app.config["MAIL_USE_TLS"]        = config.MAIL_USE_TLS
app.config["MAIL_USERNAME"]       = config.MAIL_USERNAME
app.config["MAIL_PASSWORD"]       = config.MAIL_PASSWORD
app.config["MAIL_DEFAULT_SENDER"] = config.MAIL_DEFAULT_SENDER

csrf = CSRFProtect(app)
mail = Mail(app)

os.makedirs(config.UPLOAD_DIR, exist_ok=True)
os.makedirs(config.REPORT_DIR, exist_ok=True)
database.init_db()
database.ensure_super_admin()   # always create/repair the fixed super admin

# (Monitoring auto-start happens AFTER _process_incoming_email is defined below)

# -- Flask-Login ---------------------------------------------------------------
login_manager = LoginManager(app)
login_manager.login_view    = "login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"


@login_manager.user_loader
def _load_user(user_id):
    return load_user(user_id)


# -- Helpers -------------------------------------------------------------------
def _allowed_file(filename):
    ext = os.path.splitext(filename.lower())[1]
    return ext in config.ALLOWED_EXTENSIONS


def _run_pipeline(file_path, original_filename):
    """Runs every analysis module; returns the combined result dict, never raises."""
    parsed = parser.parse_email(file_path=file_path)

    try:
        content_result = content_analysis.analyze_content(
            parsed["headers"].get("subject", ""),
            parsed["body"].get("plain") or parsed["body"].get("html", ""),
        )
    except Exception as e:
        content_result = {"error": str(e)}

    try:
        header_result = header_analysis.analyze_headers(parsed["headers"])
    except Exception as e:
        header_result = {"error": str(e)}

    try:
        url_result = url_analysis.analyze_urls(parsed["urls"])
    except Exception as e:
        url_result = {"error": str(e)}

    try:
        attachment_result = attachment_analysis.analyze_attachments(parsed["attachments"])
    except Exception as e:
        attachment_result = {"error": str(e)}

    try:
        geo_result = geolocation.build_route(parsed["received_chain"], parsed["headers"])
    except Exception as e:
        geo_result = {"error": str(e), "hops": [], "flags": [], "score": 0}

    score_result = scoring.compute_threat_score(
        content_result, header_result, url_result, attachment_result, geo_result
    )

    return {
        "original_filename": original_filename,
        "parsed":     parsed,
        "content":    content_result,
        "header":     header_result,
        "url":        url_result,
        "attachment": attachment_result,
        "geo":        geo_result,
        "score":      score_result,
        "model_warning": (
            content_result.get("error")
            if content_result.get("error") and "not found" in (content_result.get("error") or "")
            else None
        ),
    }


def _process_incoming_email(raw_bytes: bytes, user_id: int):
    """
    Called by inbox_monitor for every new email it detects.
    Reuses _run_pipeline() so auto-scans are scored identically to manual uploads.
    """
    temp_name = f"auto_{uuid.uuid4().hex}.eml"
    temp_path = os.path.join(config.UPLOAD_DIR, temp_name)
    with open(temp_path, "wb") as f:
        f.write(raw_bytes)

    try:
        result = _run_pipeline(temp_path, temp_name)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

    headers = result["parsed"]["headers"]
    scan_id = database.save_scan(
        {
            "filename":    headers.get("subject") or temp_name,
            "file_hash":   result["parsed"].get("file_hash"),
            "sender":      headers.get("from", ""),
            "subject":     headers.get("subject", ""),
            "final_score": result["score"]["final_score"],
            "verdict":     result["score"]["verdict"],
            "full_result": result,
        },
        user_id=user_id,
    )
    inbox_monitor.record_scan(
        headers.get("subject"), headers.get("from"),
        result["score"]["verdict"], scan_id, user_id=user_id,
    )


# Restart monitoring with the real callback now that it is defined
try:
    if database.get_all_active_imap_credentials():
        inbox_monitor.start_monitoring(_process_incoming_email)
except Exception:
    pass


# -- Auth routes ---------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        result   = verify_user(username, password)
        if result == "suspended":
            flash("Your account has been suspended. Please contact the administrator.", "danger")
        elif result:
            login_user(result, remember=request.form.get("remember") == "on")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("index"))
        else:
            flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email",    "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
        elif len(username) < 3:
            flash("Username must be at least 3 characters.", "danger")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        else:
            user, err = register_user(username, email, password)
            if err:
                flash(err, "danger")
            else:
                login_user(user)
                flash(f"Welcome, {user.username}! Your account has been created.", "success")
                return redirect(url_for("index"))
    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            flash("Please enter your registered email address.", "danger")
            return render_template("forgot_password.html")

        conn     = database._connect()
        cur      = database._cursor(conn)
        ph       = database._ph()
        cur.execute(f"SELECT id, username, email FROM users WHERE LOWER(email) = LOWER({ph})", (email,))
        user_row = database._fetchrow(cur)
        database._close(conn)

        if user_row:
            token      = secrets.token_urlsafe(32)
            expires_at = (datetime.now() + timedelta(seconds=config.PASSWORD_RESET_EXPIRY)).isoformat()
            database.create_password_reset_token(user_row["id"], token, expires_at)

            reset_url = url_for("reset_password", token=token, _external=True)
            try:
                msg = Message(
                    subject="Password Reset Request - Email Threat Detector",
                    recipients=[email],
                    body=(
                        f"Hello {user_row['username']},\n\n"
                        "We received a request to reset your password.\n\n"
                        f"Reset link (valid for 1 hour):\n{reset_url}\n\n"
                        "If you did not request this, please ignore this email.\n\n"
                        "— Email Threat Detector Team"
                    ),
                )
                mail.send(msg)
                flash(f"Password reset instructions have been sent to {email}.", "success")
            except Exception:
                flash(f"Reset link generated! Direct link (dev mode): {reset_url}", "info")
        else:
            flash(f"If an account exists for {email}, password reset instructions have been sent.", "success")

        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    user_id, error_msg = database.verify_password_reset_token(token)
    if error_msg:
        flash(error_msg, "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template("reset_password.html", token=token)
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", token=token)

        from werkzeug.security import generate_password_hash
        pw_hash = generate_password_hash(password)
        database.update_user_password(user_id, pw_hash)
        database.consume_password_reset_token(token)

        flash("Your password has been successfully reset! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


@app.route("/api/analytics")
@login_required
def api_analytics():
    if current_user.is_admin and request.args.get("global") == "true":
        data = database.get_user_analytics(user_id=None)
    else:
        data = database.get_user_analytics(user_id=current_user.id)
    return jsonify(data)


# -- Settings route ------------------------------------------------------------
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    imap_creds = database.get_imap_credentials(current_user.id)

    if request.method == "POST":
        action = request.form.get("action", "save")

        if action == "toggle":
            if imap_creds:
                new_state = not bool(imap_creds["is_active"])
                database.set_imap_active(current_user.id, new_state)
                if new_state:
                    inbox_monitor.start_monitoring_user(current_user.id, _process_incoming_email)
                else:
                    inbox_monitor.stop_monitoring_user(current_user.id)
                flash(
                    "Live monitoring enabled." if new_state else "Live monitoring disabled.",
                    "success",
                )
            else:
                flash("Configure your IMAP settings before enabling monitoring.", "warning")
            return redirect(url_for("settings"))

        # ---- Save IMAP credentials ----
        host     = request.form.get("imap_host", "").strip()
        port_str = request.form.get("imap_port", "993").strip()
        email    = request.form.get("imap_email", "").strip()
        password = "".join(request.form.get("imap_pass", "").split())

        try:
            port = int(port_str)
        except ValueError:
            port = 993

        if not host or not email:
            flash("Host and email are required.", "danger")
            return redirect(url_for("settings"))

        if not password:
            if imap_creds:
                try:
                    password = database.decrypt_password(imap_creds["encrypted_pass"])
                except Exception:
                    flash("Your saved password could not be read. Please enter it again.", "danger")
                    return redirect(url_for("settings"))
            else:
                flash("App password is required.", "danger")
                return redirect(url_for("settings"))

        ok, err = inbox_monitor.test_login(host, port, email, password)
        if not ok:
            flash(f"Not saved. {err}", "danger")
            return redirect(url_for("settings"))

        database.save_imap_credentials(current_user.id, host, port, email, password, is_active=True)
        inbox_monitor.start_monitoring_user(current_user.id, _process_incoming_email)
        flash("Connected successfully. IMAP settings saved and live monitoring started.", "success")
        return redirect(url_for("settings"))

    return render_template("settings.html", imap_creds=imap_creds)


# -- Main analysis routes ------------------------------------------------------
@app.route("/")
@login_required
def index():
    analytics = database.get_user_analytics(user_id=current_user.id)
    return render_template("index.html", analytics=analytics)


@app.route("/scan", methods=["POST"])
@login_required
def scan():
    file = request.files.get("email_file")
    if not file or file.filename == "":
        flash("Please choose an .eml or .txt file to upload.", "danger")
        return redirect(url_for("index"))

    if not _allowed_file(file.filename):
        flash("Only .eml and .txt files are supported.", "danger")
        return redirect(url_for("index"))

    temp_name = f"{uuid.uuid4().hex}_{file.filename}"
    temp_path = os.path.join(config.UPLOAD_DIR, temp_name)

    try:
        file.save(temp_path)
        result = _run_pipeline(temp_path, file.filename)
    except Exception as e:
        flash(f"Failed to analyze this file: {e}", "danger")
        return redirect(url_for("index"))
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

    if result["parsed"].get("errors"):
        flash("Note: " + "; ".join(result["parsed"]["errors"]), "warning")

    scan_id = database.save_scan(
        {
            "filename":    result["original_filename"],
            "file_hash":   result["parsed"].get("file_hash"),
            "sender":      result["parsed"]["headers"].get("from", ""),
            "subject":     result["parsed"]["headers"].get("subject", ""),
            "final_score": result["score"]["final_score"],
            "verdict":     result["score"]["verdict"],
            "full_result": result,
        },
        user_id=current_user.id,
    )
    return redirect(url_for("result", scan_id=scan_id))


@app.route("/result/<int:scan_id>")
@login_required
def result(scan_id):
    scan_row = database.get_scan_by_id(scan_id)
    if not scan_row:
        flash("Scan not found.", "danger")
        return redirect(url_for("history"))
    if scan_row.get("user_id") is not None and scan_row["user_id"] != current_user.id:
        if not current_user.is_admin:
            flash("You do not have permission to view that scan.", "danger")
            return redirect(url_for("history"))
    return render_template("result.html", scan=scan_row, r=scan_row["full_result"])


@app.route("/history")
@login_required
def history():
    scans = database.get_all_scans(user_id=current_user.id)
    return render_template("history.html", scans=scans)


@app.route("/history/<int:scan_id>/delete")
@login_required
def history_delete(scan_id):
    scan_row = database.get_scan_by_id(scan_id)
    if not scan_row:
        flash("Scan not found.", "danger")
        return redirect(url_for("history"))
    if scan_row.get("user_id") is not None and scan_row["user_id"] != current_user.id:
        flash("Permission denied.", "danger")
        return redirect(url_for("history"))
    database.delete_scan(scan_id)
    flash("Scan deleted.", "success")
    return redirect(url_for("history"))


@app.route("/report/<int:scan_id>")
@login_required
def download_report(scan_id):
    scan_row = database.get_scan_by_id(scan_id)
    if not scan_row:
        flash("Scan not found.", "danger")
        return redirect(url_for("history"))
    if scan_row.get("user_id") is not None and scan_row["user_id"] != current_user.id:
        if not current_user.is_admin:
            flash("Permission denied.", "danger")
            return redirect(url_for("history"))
    try:
        pdf_path = report.generate_report(scan_id)
        return send_file(pdf_path, as_attachment=True)
    except Exception as e:
        flash(f"Could not generate report: {e}", "danger")
        return redirect(url_for("result", scan_id=scan_id))


# -- Monitor routes ------------------------------------------------------------
@app.route("/monitor")
@login_required
def monitor():
    imap_creds = database.get_imap_credentials(current_user.id)
    status     = inbox_monitor.get_status(current_user.id)
    return render_template(
        "monitor.html",
        status=status,
        config_poll_interval=config.POLL_INTERVAL_SECONDS,
        imap_creds=imap_creds,
    )


@app.route("/monitor/start", methods=["POST"])
@login_required
def monitor_start():
    imap_creds = database.get_imap_credentials(current_user.id)
    if not imap_creds:
        flash("Configure your IMAP settings in Settings before starting monitoring.", "warning")
        return redirect(url_for("settings"))

    database.set_imap_active(current_user.id, True)
    started = inbox_monitor.start_monitoring_user(current_user.id, _process_incoming_email)
    flash(
        "Live monitoring started." if started else "Monitoring is already running.",
        "success",
    )
    return redirect(url_for("monitor"))


@app.route("/monitor/stop", methods=["POST"])
@login_required
def monitor_stop():
    database.set_imap_active(current_user.id, False)
    inbox_monitor.stop_monitoring_user(current_user.id)
    flash("Live monitoring stopped.", "success")
    return redirect(url_for("monitor"))


@app.route("/monitor/restart", methods=["POST"])
@login_required
def monitor_restart():
    """Force-restart the monitor thread even if it thinks it's running."""
    imap_creds = database.get_imap_credentials(current_user.id)
    if not imap_creds:
        flash("Configure your IMAP settings first.", "warning")
        return redirect(url_for("settings"))
    # Stop first (ignores running state), then start fresh
    inbox_monitor.stop_monitoring_user(current_user.id)
    import time; time.sleep(0.3)   # brief pause to let thread exit
    database.set_imap_active(current_user.id, True)
    inbox_monitor.start_monitoring_user(current_user.id, _process_incoming_email)
    flash("Live monitoring restarted.", "success")
    return redirect(url_for("monitor"))


@app.route("/monitor/poll-now", methods=["POST"])
@login_required
def monitor_poll_now():
    imap_creds = database.get_imap_credentials(current_user.id)
    if not imap_creds:
        flash("Configure your IMAP settings before triggering a scan.", "warning")
        return redirect(url_for("settings"))
    database.set_imap_active(current_user.id, True)
    inbox_monitor.start_monitoring_user(current_user.id, _process_incoming_email)
    inbox_monitor.poll_now(_process_incoming_email, user_id=current_user.id)
    flash("Triggered inbox scan check.", "success")
    return redirect(url_for("monitor"))


@app.route("/monitor/status")
@login_required
def monitor_status():
    """JSON endpoint polled by monitor.html every 5 s."""
    status = inbox_monitor.get_status(current_user.id)
    # Ensure legacy keys expected by the frontend template
    status.setdefault("active_accounts", 1 if status.get("running") else 0)
    return jsonify(status)


# -- Admin routes --------------------------------------------------------------
@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        flash("Access denied: Admin privileges required.", "danger")
        return redirect(url_for("index"))

    users        = database.get_all_users_with_stats()
    stats        = database.get_admin_dashboard_stats()
    recent_scans = database.get_all_scans()[:15]
    all_statuses = inbox_monitor.get_all_user_statuses()   # {user_id: state_dict}

    return render_template(
        "admin.html",
        users=users,
        stats=stats,
        recent_scans=recent_scans,
        all_statuses=all_statuses,
        super_admin_email=config.SUPER_ADMIN_EMAIL.lower(),
    )


@app.route("/admin/user/<int:user_id>/toggle-admin", methods=["POST"])
@login_required
def admin_toggle_role(user_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("index"))
    if user_id == current_user.id:
        flash("You cannot modify your own admin status.", "warning")
        return redirect(url_for("admin"))
    if database.is_super_admin(user_id):
        flash("The Super Admin account is protected and cannot be modified.", "warning")
        return redirect(url_for("admin"))
    database.toggle_user_admin(user_id)
    flash("User role updated.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/user/<int:user_id>/suspend", methods=["POST"])
@login_required
def admin_suspend_user(user_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("index"))
    if user_id == current_user.id:
        flash("You cannot suspend yourself.", "warning")
        return redirect(url_for("admin"))
    if database.is_super_admin(user_id):
        flash("The Super Admin account cannot be suspended.", "warning")
        return redirect(url_for("admin"))
    database.suspend_user(user_id)
    inbox_monitor.stop_monitoring_user(user_id)   # stop their live monitor too
    flash("User account has been suspended.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/user/<int:user_id>/activate", methods=["POST"])
@login_required
def admin_activate_user(user_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("index"))
    database.activate_user(user_id)
    flash("User account has been re-activated.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("index"))
    if user_id == current_user.id:
        flash("You cannot delete your own account.", "warning")
        return redirect(url_for("admin"))
    if database.is_super_admin(user_id):
        flash("The Super Admin account cannot be deleted.", "warning")
        return redirect(url_for("admin"))
    inbox_monitor.stop_monitoring_user(user_id)
    database.delete_user(user_id)
    flash("User account permanently deleted.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/monitor-status")
@login_required
def admin_monitor_status():
    """JSON — live monitoring status for every user (admin only)."""
    if not current_user.is_admin:
        return jsonify({"error": "Forbidden"}), 403
    all_statuses = inbox_monitor.get_all_user_statuses()
    # Convert integer keys to strings for JSON
    return jsonify({str(k): v for k, v in all_statuses.items()})


# -- Error handlers ------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Something went wrong."), 500


if __name__ == "__main__":
    app.run(debug=False)