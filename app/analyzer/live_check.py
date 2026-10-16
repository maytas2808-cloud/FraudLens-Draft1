"""Network checks: the HTTPS certificate check, plus optional redirect following and domain age (RDAP).

Only public internet addresses are contacted (private, loopback and link-local
addresses are refused) and response bodies are never downloaded or stored.
"""
import http.client
import ipaddress
import json
import socket
import ssl
import time
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

TIMEOUT = 4
TLS_TIMEOUT = 3
TLS_CACHE_SECONDS = 600
MAX_HOPS = 5
UA = "Mozilla/5.0 (compatible; FraudLens-safety-check/1.0)"
_tls_cache: dict[tuple[str, int], tuple[float, dict]] = {}


class BlockedAddress(Exception):
    pass


def _check_public(host: str, port: int) -> None:
    for info in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast:
            raise BlockedAddress(f"{host} resolves to a non-public address")


def _one_request(url: str) -> tuple[int, str | None]:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("unsupported URL")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    _check_public(parts.hostname, port)
    conn_cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    kwargs = {"timeout": TIMEOUT}
    if parts.scheme == "https":
        kwargs["context"] = ssl.create_default_context()
    conn = conn_cls(parts.hostname, port, **kwargs)
    try:
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        conn.request("GET", path, headers={"User-Agent": UA, "Accept": "text/html"})
        resp = conn.getresponse()
        return resp.status, resp.getheader("Location")
    finally:
        conn.close()


def follow_redirects(url: str) -> dict:
    chain, current = [], url if "://" in url else "https://" + url
    result = {"chain": chain, "final_url": None, "https_ok": None, "error": None}
    for _ in range(MAX_HOPS + 1):
        try:
            status, location = _one_request(current)
        except ssl.SSLError as e:
            result["https_ok"] = False
            result["error"] = f"TLS certificate problem: {e.reason or e}"
            return result
        except BlockedAddress as e:
            result["error"] = str(e)
            return result
        except (OSError, ValueError, http.client.HTTPException) as e:
            result["error"] = f"Could not reach the site ({type(e).__name__})"
            return result
        chain.append({"url": current, "status": status})
        if current.startswith("https://"):
            result["https_ok"] = True
        if status in (301, 302, 303, 307, 308) and location:
            current = urljoin(current, location)
            continue
        break
    result["final_url"] = chain[-1]["url"] if chain else None
    return result


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=TLS_TIMEOUT):
            return True
    except OSError:
        return False


def _check_certificate(host: str, port: int) -> dict:
    result = {"status": "unreachable", "issuer": None, "expires": None, "days_left": None, "error": None}
    try:
        _check_public(host, port)
    except BlockedAddress as e:
        result.update(status="blocked", error=str(e))
        return result
    except OSError:
        result["error"] = "The domain does not resolve"
        return result
    try:
        with socket.create_connection((host, port), timeout=TLS_TIMEOUT) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
    except ssl.SSLCertVerificationError as e:
        result.update(status="invalid", error=e.verify_message or str(e.reason or e))
        return result
    except ssl.SSLError as e:
        result.update(status="no_https", error=f"HTTPS handshake failed ({e.reason or e})")
        return result
    except ConnectionRefusedError:
        result.update(status="no_https" if _port_open(host, 80) else "unreachable",
                      error=f"Nothing answers on port {port}")
        return result
    except OSError as e:
        reachable = _port_open(host, 80)
        result.update(status="no_https" if reachable else "unreachable",
                      error=f"No HTTPS answer ({type(e).__name__})" if reachable else f"Could not reach the site ({type(e).__name__})")
        return result
    issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
    result["status"] = "valid"
    result["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
    if cert.get("notAfter"):
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
        result["expires"] = expires.date().isoformat()
        result["days_left"] = (expires - datetime.now(timezone.utc)).days
    return result


def check_certificate(host: str, port: int = 443) -> dict:
    """Open a TLS connection and verify the certificate against the system trust store and hostname.

    status: valid | invalid | no_https | unreachable | blocked. Results are cached per host for a few minutes.
    """
    key = (host.lower(), port)
    hit = _tls_cache.get(key)
    if hit and time.monotonic() - hit[0] < TLS_CACHE_SECONDS:
        return dict(hit[1])
    result = _check_certificate(host, port)
    if len(_tls_cache) >= 1000:
        _tls_cache.clear()
    _tls_cache[key] = (time.monotonic(), result)
    return dict(result)


def domain_age_days(registered_domain: str) -> int | None:
    req = urllib.request.Request(f"https://rdap.org/domain/{registered_domain}", headers={"User-Agent": UA, "Accept": "application/rdap+json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = json.loads(r.read(500_000))
    except (OSError, ValueError):
        return None
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            try:
                created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            except ValueError:
                return None
            return (datetime.now(timezone.utc) - created).days
    return None
