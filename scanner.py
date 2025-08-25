# scanner.py
import requests
import ssl
import socket
from urllib.parse import urlparse

def check_security_headers(url):
    """Check for missing common security headers."""
    issues = []
    try:
        response = requests.get(url, timeout=10)

        headers = response.headers
        required_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]

        for h in required_headers:
            if h not in headers:
                issues.append({
                    "title": f"Missing Security Header: {h}",
                    "severity": "Medium"
                })

    except Exception as e:
        issues.append({
            "title": f"Header check failed: {e}",
            "severity": "Low"
        })
    return issues


def check_tls_version(url):
    """Check if server supports weak TLS versions."""
    issues = []
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443

        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                if version not in ["TLSv1.2", "TLSv1.3"]:
                    issues.append({
                        "title": f"Weak TLS Version Detected: {version}",
                        "severity": "High"
                    })
    except Exception as e:
        issues.append({
            "title": f"TLS check failed: {e}",
            "severity": "Low"
        })
    return issues


def run_scan(url):
    """Run all mini security checks and return issues."""
    results = []
    results.extend(check_security_headers(url))
    results.extend(check_tls_version(url))

    if not results:
        results.append({
            "title": "No major issues found 🎉",
            "severity": "Info"
        })
    return results

