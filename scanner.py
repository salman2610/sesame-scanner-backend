# scanner.py
from __future__ import annotations
import re
import socket
import ssl
from typing import List, Dict, Any
from urllib.parse import urlparse
import requests

HTTP_TIMEOUT = 4
TLS_TIMEOUT = 3

TECH_PATTERNS = {
    "WordPress": re.compile(r"wp-content|wp-includes|wordpress", re.I),
    "Joomla": re.compile(r"Joomla|com_content", re.I),
    "Drupal": re.compile(r"Drupal", re.I),
    "Apache": re.compile(r"Apache", re.I),
    "nginx": re.compile(r"nginx", re.I),
    "PHP": re.compile(r"PHP/([0-9.]+)", re.I),
    "jQuery": re.compile(r"jquery(?:-|\.)([0-9.]+)", re.I)
}

def normalize(url: str) -> str:
    u = url.strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u

def fetch_home(url: str) -> Dict[str, Any]:
    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent":"SesameScanner/1.0"})
        return {"status": r.status_code, "headers": dict(r.headers), "text": r.text or ""}
    except Exception as e:
        return {"status": None, "headers": {}, "text": "", "error": str(e)}

def check_tls(hostname: str) -> Dict[str, Any]:
    out = {"issuer": None, "notBefore": None, "notAfter": None, "protocol": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                out["protocol"] = ssock.version()
                issuer_pairs = cert.get("issuer", ())
                issuer = {k:v for t in issuer_pairs for k,v in t} if issuer_pairs else {}
                out["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
                out["notBefore"] = cert.get("notBefore")
                out["notAfter"] = cert.get("notAfter")
    except Exception as e:
        out["error"] = str(e)
    return out

def detect_tech(headers: dict, html: str) -> List[str]:
    combined = " ".join([headers.get("Server",""), headers.get("X-Powered-By",""), html or ""])
    found = []
    for name, pat in TECH_PATTERNS.items():
        if pat.search(combined):
            found.append(name)
    return found

def check_files(url: str) -> List[Dict[str, Any]]:
    results = []
    for p in ["/robots.txt", "/sitemap.xml"]:
        try:
            r = requests.get(url.rstrip("/") + p, timeout=HTTP_TIMEOUT, headers={"User-Agent":"SesameScanner/1.0"})
            if r.status_code == 200:
                results.append({"path": p, "size": len(r.text)})
        except Exception:
            pass
    return results

def run_scan(raw_url: str) -> List[Dict[str, Any]]:
    """
    Return list of findings (each is a dict with keys: type, title, severity, description).
    This function is intentionally lightweight and non-intrusive.
    """
    url = normalize(raw_url)
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    findings: List[Dict[str, Any]] = []

    # Fetch homepage
    home = fetch_home(url)
    if home.get("status") is None:
        findings.append({"type":"error", "title":"Fetch failed", "severity":"High", "description": home.get("error", "unknown error")})
        return findings

    headers = home.get("headers", {})
    html = home.get("text", "")

    # Missing security headers
    sec_headers = [
        ("Content-Security-Policy", "CSP"),
        ("Strict-Transport-Security", "HSTS"),
        ("Referrer-Policy", "Referrer-Policy"),
        ("X-Frame-Options", "X-Frame-Options"),
        ("X-Content-Type-Options", "X-Content-Type-Options")
    ]
    missing = [friendly for name,friendly in sec_headers if name not in headers]
    if missing:
        findings.append({
            "type":"missing-header",
            "title":"Missing security headers",
            "severity":"Medium",
            "description": f"Missing: {', '.join(missing)}"
        })

    # Server header leak
    if headers.get("Server"):
        findings.append({
            "type":"server-banner",
            "title":"Server header exposed",
            "severity":"Low",
            "description": f"Server header: {headers.get('Server')}"
        })

    # Files (robots/sitemap)
    files = check_files(url)
    for f in files:
        findings.append({
            "type":"file",
            "title": f"Found {f['path']}",
            "severity":"Info",
            "description": f"{f['path']} ({f['size']} bytes)"
        })

    # Directory listing hint
    if "Index of /" in html or re.search(r"Directory listing for", html, re.I):
        findings.append({
            "type":"dir-listing",
            "title":"Possible directory listing",
            "severity":"Medium",
            "description":"Page contains 'Index of /' or directory listing content"
        })

    # Tech detection
    tech = detect_tech(headers, html)
    if tech:
        findings.append({
            "type":"tech",
            "title":"Tech stack detected",
            "severity":"Info",
            "description": ", ".join(tech)
        })

    # TLS check (if https)
    if parsed.scheme == "https" and hostname:
        tls = check_tls(hostname)
        if tls.get("error"):
            findings.append({
                "type":"tls",
                "title":"TLS info retrieval failed",
                "severity":"Low",
                "description": tls.get("error")
            })
        else:
            findings.append({
                "type":"tls",
                "title":"TLS certificate",
                "severity":"Info",
                "description": f"Issuer: {tls.get('issuer')}, valid: {tls.get('notBefore')} → {tls.get('notAfter')}, proto: {tls.get('protocol')}"
            })
    else:
        findings.append({
            "type":"tls",
            "title":"Non-HTTPS",
            "severity":"Medium",
            "description":"Target is not HTTPS; TLS checks skipped"
        })

    # If no findings, say so
    if not findings:
        findings.append({"type":"info","title":"No issues in quick scan","severity":"Info","description":"No obvious issues were detected in the lightweight scan."})

    return findings
