"""Network helpers: HTTP client, DNS resolution, input validation."""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import threading
from typing import Any
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

from .config import CONFIG

USER_AGENT = CONFIG.user_agent

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9\-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9\-]{1,63}(?<!-))+\.?$")
VIN_RE = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$", re.IGNORECASE)
IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


class Cancelled(Exception):
    """Raised inside a module when the user stops a running job."""


def new_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    })
    adapter = HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=1)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


_local = threading.local()


def session_for_thread() -> requests.Session:
    """One pooled session per thread: requests.Session is not thread-safe."""
    session = getattr(_local, "session", None)
    if session is None:
        session = new_session()
        _local.session = session
    return session


class HttpError(Exception):
    pass


def http(url: str, *, method: str = "GET", timeout: float | None = None,
         session: requests.Session | None = None, allow_status: tuple[int, ...] = (),
         proxy: str | None = None, **kwargs: Any) -> requests.Response:
    client = session or session_for_thread()
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        response = client.request(
            method, url, timeout=timeout or CONFIG.timeout, proxies=proxies, **kwargs
        )
    except requests.exceptions.SSLError:
        try:
            return client.request(
                method, url, timeout=timeout or CONFIG.timeout, proxies=proxies,
                verify=False, **kwargs
            )
        except requests.RequestException as exc:
            raise HttpError(str(exc)) from exc
    except requests.RequestException as exc:
        raise HttpError(str(exc)) from exc
    if response.status_code >= 400 and response.status_code not in allow_status:
        raise HttpError(f"HTTP {response.status_code} for {response.url}")
    return response


def get_json(url: str, **kwargs: Any) -> Any:
    response = http(url, **kwargs)
    try:
        return response.json()
    except ValueError as exc:
        raise HttpError(f"Invalid JSON from {url}") from exc


def resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    seen: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    return seen


def reverse_dns(ip: str) -> list[str]:
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, OSError):
        return []
    return [host, *aliases]


def tls_certificate(host: str, port: int = 443) -> dict[str, Any]:
    """Return certificate details. Falls back to an unverified handshake and says so."""
    verified = True
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=CONFIG.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                info = {
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": cert.get("subjectAltName"),
                    "version": tls.version(),
                    "cipher": tls.cipher()[0] if tls.cipher() else None,
                }
    except ssl.SSLCertVerificationError:
        verified = False
        loose = ssl.create_default_context()
        loose.check_hostname = False
        loose.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=CONFIG.timeout) as sock:
            with loose.wrap_socket(sock, server_hostname=host) as tls:
                info = {
                    "subject": (), "issuer": (), "not_before": "", "not_after": "",
                    "san": (), "version": tls.version(),
                    "cipher": tls.cipher()[0] if tls.cipher() else None,
                }
    info["verified"] = verified
    return info


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_target(value: str) -> str:
    value = value.strip()
    if "://" in value:
        return urlparse(value).hostname or value
    return value.split("/")[0]


def serve_url(url: str) -> str:
    return url if url.startswith(("http://", "https://")) else "https://" + url


def geo_summary(lat: float, lon: float) -> str:
    return f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=13/{lat}/{lon}"
