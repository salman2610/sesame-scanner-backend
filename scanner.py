# scanner.py
import re
import socket
import ssl
import time
from urllib.parse import urlparse
import requests

HTTP_TIMEOUT = 6
TLS_TIMEOUT = 4

SECURITY_HEADERS = [
    ("Content-Security-Policy", "CSP"),
    ("Strict-Transport-Security", "HSTS"),
    ("Referrer-Policy", "Referrer-Policy"),
    ("X-Frame-Options", "X-Frame-Options"),
    ("X-Content-Type-Options", "X-Content-Type-Options"),
]

TECH_HINTS = [
    ("WordPress", re.compile(r"wp-content|wp-includes|wordpress", re.I)),
    ("Joomla", re.compile(r"Joomla|com_content", re.I)),
    ("Drupal", re.compile(r"Drupal", re.I)),
    ("Apache", re.compile(r"Apache", re.I)),
    ("nginx", re.compile(r"nginx", re.I)),
    ("PHP", re.compile(r"PHP", re.I)),
]


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        return "https://" + raw
    return raw


def get(url: str):
    """GET with a tight timeout and a clean headers dict."""
    r = requests.get(
        url,
        timeout=HTTP_TIMEOUT,
        allow_redirects=True,
        headers={"User-Agent": "SesameScanner/1.0"},
    )
    return r.status_code, {k: v for k, v in r.headers.items()}, r.text or ""


def check_tls(hostname: str):
    info = {"issuer": None, "notBefore": None, "notAfter": None, "protocol": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                def pairs_to_dict(pairs):
                    return {k: v for t in pairs for k, v in t} if pairs else {}
                issuer = pairs_to_dict(cert.get("issuer", ()))
                info.update({
                    "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "protocol": proto,
                })
    except Exception as e:
        info["error"] = str(e)
    return info


def scan(url: str) -> dict:
    start = time.time()
    url = normalize_url(url)
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    issues = []  # each item: {type, message}

    # Fetch homepage
    try:
        status, headers, html = get(url)
    except Exception as e:
        return {
            "target": url,
            "runtime_seconds": round(time.time() - start, 2),
            "issues_preview": [
                {"type": "error", "message": f"Failed to fetch: {e}"}
            ],
            "locked_count": 0,
            "note": "Contact Sesame for full assessment.",
        }

    # 1) Missing security headers
    missing = []
    for h, friendly in SECURITY_HEADERS:
        if h not in headers:
            missing.append(friendly)
    if missing:
        issues.append({
            "type": "missing-header",
            "message": f"Missing security headers: {', '.join(missing)}",
        })

    # 2) TLS quick check (only if https)
    if parsed.scheme == "https" and hostname:
        tls = check_tls(hostname)
        if tls.get("error"):
            issues.append({"type": "tls", "message": f"TLS check failed: {tls['error']}"})
        else:
            issues.append({
                "type": "tls",
                "message": f"TLS issuer: {tls.get('issuer')}, valid: {tls.get('notBefore')} to {tls.get('notAfter')}, proto: {tls.get('protocol')}",
            })
    else:
        issues.append({"type": "tls", "message": "Site not using HTTPS (TLS skipped)"})

    # 3) Directory listing hint
    if status == 200 and "Index of /" in html:
        issues.append({"type": "dir", "message": "Possible directory listing enabled (Index of /)"})

    # 4) Server header disclosure
    if headers.get("Server"):
        issues.append({"type": "server-info", "message": f"Server header exposes: {headers['Server']}"})

    # 5) Simple tech hints from headers + html
    combined = " ".join([headers.get("Server", ""), headers.get("X-Powered-By", ""), html])
    tech_detected = set([name for name, pat in TECH_HINTS if pat.search(combined)])
    if tech_detected:
        issues.append({"type": "tech", "message": f"Detected: {', '.join(sorted(tech_detected))}"})

    # Build preview (limit to 4)
    preview = issues[:4]
    locked = max(0, len(issues) - len(preview))

    return {
        "target": url,
        "runtime_seconds": round(time.time() - start, 2),
        "issues_preview": preview,
        "locked_count": locked,
        "note": "Contact Sesame for full assessment.",
    }
