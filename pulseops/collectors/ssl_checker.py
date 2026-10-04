import ssl
import socket
import subprocess
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

def parse_ssl_expiry_date(date_str: str) -> Optional[int]:
    """Parses an SSL expiry date string (like 'Oct 28 12:00:00 2026 GMT') and returns days remaining."""
    if not date_str:
        return None
    try:
        # Standard SSL date format: "May 25 12:00:00 2026 GMT"
        # Try multiple formats
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S"):
            try:
                # Remove extra spaces if day has leading space
                clean_str = " ".join(date_str.split())
                exp_date = datetime.strptime(clean_str, fmt).replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                delta = exp_date - now
                return max(0, delta.days)
            except ValueError:
                continue
    except Exception:
        pass
    return None

class SSLChecker:
    """Checks SSL certificate validity and days until expiration."""

    def check_domain(self, domain: str, timeout: float = 2.0) -> Optional[int]:
        """Queries the live domain over HTTPS port 443 to read cert expiration."""
        # Skip dummy/local test domains
        if domain.endswith(".local") or domain in ("localhost", "127.0.0.1"):
            return None
            
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert and "notAfter" in cert:
                        return parse_ssl_expiry_date(cert["notAfter"])
        except Exception:
            return None
        return None

    def check_cert_file(self, cert_path: str | Path) -> Optional[int]:
        """Reads expiration from a local PEM/CRT file via openssl if available."""
        p = Path(cert_path)
        if not p.exists():
            return None
            
        if shutil.which("openssl"):
            try:
                res = subprocess.run(
                    ["openssl", "x509", "-enddate", "-noout", "-in", str(p)],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if res.returncode == 0 and "notAfter=" in res.stdout:
                    raw_date = res.stdout.split("notAfter=", 1)[1].strip()
                    return parse_ssl_expiry_date(raw_date)
            except Exception:
                pass
        return None
