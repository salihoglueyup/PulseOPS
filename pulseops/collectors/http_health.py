import time
import urllib.request
import urllib.error
from typing import Tuple, Optional
from pulseops.models.proxy import ProxyRoute

class HTTPHealthChecker:
    """Checks responsiveness of local backend targets to detect 502/504 Bad Gateways."""

    def check_url(self, target_url: str, timeout: float = 1.0) -> Tuple[Optional[int], Optional[float]]:
        start = time.time()
        try:
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": "ServerTUI-HealthChecker/1.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                elapsed_ms = (time.time() - start) * 1000.0
                return resp.status, round(elapsed_ms, 1)
        except urllib.error.HTTPError as e:
            elapsed_ms = (time.time() - start) * 1000.0
            return e.code, round(elapsed_ms, 1)
        except (urllib.error.URLError, ConnectionRefusedError, TimeoutError, OSError):
            elapsed_ms = (time.time() - start) * 1000.0
            # Backend process down while proxy is routing to it = 502 Bad Gateway
            return 502, round(elapsed_ms, 1)
        except Exception:
            return None, None

    def enrich_routes_simulated(self, routes: list[ProxyRoute]) -> list[ProxyRoute]:
        """Provides simulated health checks for testing and demo mode."""
        enriched: list[ProxyRoute] = []
        for r in routes:
            r_copy = r.model_copy()
            if "blog" in r.domain:
                r_copy.http_status = 502
                r_copy.response_time_ms = 45.0
            else:
                r_copy.http_status = 200
                r_copy.response_time_ms = 14.2
            enriched.append(r_copy)
        return enriched

    def enrich_routes_live(self, routes: list[ProxyRoute]) -> list[ProxyRoute]:
        """Performs live health checks against each proxy route."""
        enriched: list[ProxyRoute] = []
        for r in routes:
            r_copy = r.model_copy()
            if r.target_url.startswith("http://") or r.target_url.startswith("https://"):
                status, elapsed = self.check_url(r.target_url)
                r_copy.http_status = status
                r_copy.response_time_ms = elapsed
            enriched.append(r_copy)
        return enriched
