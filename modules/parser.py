"""
parser.py
---------
Turns a raw .eml file (or raw email text) into one clean Python dictionary
that every other module in this project reads from. Nothing else in the
project should touch Python's `email` library directly - everyone reads
the dictionary this file produces.
"""

import re
import hashlib
import email
from email import policy
from email.utils import parseaddr, getaddresses

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


def file_sha256(file_path):
    """Hash of the ORIGINAL uploaded file - proves the evidence wasn't altered."""
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _domain_of(addr):
    """Pull just the domain out of an email address string."""
    if not addr or "@" not in addr:
        return ""
    return addr.split("@")[-1].strip().lower()


def extract_headers(msg):
    """Pull out every header field the rest of the project cares about."""
    from_raw = msg.get("From", "")
    from_name, from_email = parseaddr(from_raw)
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")

    auth_results = msg.get("Authentication-Results", "") or ""
    received_spf = msg.get("Received-SPF", "") or ""

    return {
        "from": from_raw,
        "from_name": from_name,
        "from_email": from_email.lower(),
        "from_domain": _domain_of(from_email),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", "") or "",
        "date": msg.get("Date", ""),
        "reply_to": reply_to,
        "reply_to_email": parseaddr(reply_to)[1].lower(),
        "reply_to_domain": _domain_of(parseaddr(reply_to)[1]),
        "return_path": return_path,
        "return_path_email": parseaddr(return_path)[1].lower(),
        "return_path_domain": _domain_of(parseaddr(return_path)[1]),
        "message_id": msg.get("Message-ID", ""),
        "authentication_results": auth_results,
        "received_spf": received_spf,
        "dkim_signature_present": msg.get("DKIM-Signature") is not None,
    }


def extract_body(msg):
    """Return the plain-text and HTML parts of the email body separately."""
    plain, html = "", ""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = str(part.get("Content-Disposition", "")).lower()
                if "attachment" in disp:
                    continue
                try:
                    payload = part.get_content()
                except Exception:
                    continue
                if ctype == "text/plain" and not plain:
                    plain = payload
                elif ctype == "text/html" and not html:
                    html = payload
        else:
            ctype = msg.get_content_type()
            payload = msg.get_content()
            if ctype == "text/html":
                html = payload
            else:
                plain = payload
    except Exception:
        pass
    return {"plain": plain or "", "html": html or ""}


def extract_urls(plain, html):
    """
    Find every link in the email. For HTML links we keep BOTH the real
    href and the visible anchor text, because a mismatch between the two
    (text says "bank.com", link goes to an IP) is a strong phishing signal
    used later in url_analysis.py.
    """
    urls = []
    seen = set()
    url_regex = re.compile(r'https?://[^\s"\'<>\)]+', re.IGNORECASE)

    for match in url_regex.findall(plain or ""):
        clean = match.rstrip(".,;:!?")
        if clean not in seen:
            seen.add(clean)
            urls.append({"url": clean, "anchor_text": None, "source": "plain"})

    if html and HAS_BS4:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if not href.lower().startswith(("http://", "https://")):
                    continue
                if href not in seen:
                    seen.add(href)
                    urls.append({
                        "url": href,
                        "anchor_text": a.get_text(strip=True) or None,
                        "source": "html",
                    })
        except Exception:
            pass
    elif html:
        for match in url_regex.findall(html):
            clean = match.rstrip(".,;:!?\"'")
            if clean not in seen:
                seen.add(clean)
                urls.append({"url": clean, "anchor_text": None, "source": "html"})

    return urls


def extract_attachments(msg):
    """
    Hash and describe attachments WITHOUT ever saving or opening them.
    Everything stays in memory.
    """
    attachments = []
    try:
        for part in msg.walk():
            disp = str(part.get("Content-Disposition", "")) or ""
            filename = part.get_filename()
            if not filename and "attachment" not in disp.lower():
                continue
            if not filename:
                continue
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
            })
    except Exception:
        pass
    return attachments


def extract_received_chain(msg):
    """
    Raw Received header strings, kept in their ORIGINAL order (newest/last
    hop first, as they appear in the file). geolocation.py reverses this
    later to walk from origin to destination.
    """
    try:
        return [str(h) for h in msg.get_all("Received", [])]
    except Exception:
        return []


def parse_email(file_path=None, raw_text=None):
    """
    Main entry point. Give it EITHER a file_path OR raw_text.
    Returns the single dictionary every other module consumes.
    """
    errors = []
    file_hash = file_sha256(file_path) if file_path else None

    try:
        if file_path:
            with open(file_path, "rb") as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
        elif raw_text:
            msg = email.message_from_string(raw_text, policy=policy.default)
        else:
            raise ValueError("Provide either file_path or raw_text")
    except Exception as e:
        return {
            "file_hash": file_hash,
            "headers": {},
            "received_chain": [],
            "body": {"plain": "", "html": ""},
            "urls": [],
            "attachments": [],
            "errors": [f"Failed to parse email: {e}"],
        }

    try:
        headers = extract_headers(msg)
    except Exception as e:
        headers = {}
        errors.append(f"Header extraction failed: {e}")

    try:
        body = extract_body(msg)
    except Exception as e:
        body = {"plain": "", "html": ""}
        errors.append(f"Body extraction failed: {e}")

    try:
        urls = extract_urls(body.get("plain", ""), body.get("html", ""))
    except Exception as e:
        urls = []
        errors.append(f"URL extraction failed: {e}")

    try:
        attachments = extract_attachments(msg)
    except Exception as e:
        attachments = []
        errors.append(f"Attachment extraction failed: {e}")

    try:
        received_chain = extract_received_chain(msg)
    except Exception as e:
        received_chain = []
        errors.append(f"Received-chain extraction failed: {e}")

    return {
        "file_hash": file_hash,
        "headers": headers,
        "received_chain": received_chain,
        "body": body,
        "urls": urls,
        "attachments": attachments,
        "errors": errors,
    }
