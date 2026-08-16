"""Safety guardrail: only allow scanning local or explicitly authorized targets.

A target is authorized only when EITHER:
  1. every IP its host resolves to is loopback / private / link-local, OR
  2. its host is present in an explicit allowlist supplied by the caller.

Public hostnames are rejected by default. This is the single choke point that
every scan must pass through before the scanner is ever launched.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

ALLOWED_SCHEMES = ("http", "https")


class TargetNotAuthorizedError(Exception):
    """Raised when a target fails the safety check."""


@dataclass(frozen=True)
class AuthorizedTarget:
    url: str
    host: str
    reason: str


def _is_local_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return ip.is_loopback or ip.is_private or ip.is_link_local


def _resolve_ips(host: str) -> list[str]:
    """Resolve a host to all its IPs. Literal IPs pass straight through."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    infos = socket.getaddrinfo(host, None)
    # sockaddr is (ip, port) for v4 and (ip, port, flow, scope) for v6.
    return sorted({info[4][0] for info in infos})


def authorize_target(
    url: str,
    allowlist: set[str] | None = None,
) -> AuthorizedTarget:
    """Validate a target URL. Returns an AuthorizedTarget or raises.

    allowlist: hostnames (case-insensitive) explicitly cleared for scanning,
               e.g. a staging domain you own. These bypass the private-IP rule.
    """
    allowlist = {h.lower() for h in (allowlist or set())}

    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise TargetNotAuthorizedError(
            f"URL must start with http:// or https:// — got {url!r}"
        )

    host = (parsed.hostname or "").lower()
    if not host:
        raise TargetNotAuthorizedError(f"Could not parse a host from {url!r}")

    # 1) Explicit allowlist wins — this is the "authorized target" escape hatch.
    if host in allowlist:
        return AuthorizedTarget(url=url, host=host, reason=f"host {host!r} is allowlisted")

    # 2) Otherwise every resolved IP must be local.
    try:
        ips = _resolve_ips(host)
    except socket.gaierror as exc:
        raise TargetNotAuthorizedError(
            f"Could not resolve host {host!r}; refusing to scan ({exc})"
        ) from exc

    if not ips:
        raise TargetNotAuthorizedError(f"Host {host!r} resolved to no addresses")

    public = [ip for ip in ips if not _is_local_ip(ip)]
    if public:
        raise TargetNotAuthorizedError(
            f"Host {host!r} resolves to non-local address(es) {public}. "
            f"Only loopback/private targets are allowed, or add {host!r} to the "
            f"allowlist if you are authorized to scan it."
        )

    return AuthorizedTarget(
        url=url, host=host, reason=f"host {host!r} resolves to local IP(s) {ips}"
    )
