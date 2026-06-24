# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
SSRF-safe target validation for scan assets.

Returns a ValidationResult that pins the IP address resolved at validation
time. The scanner must connect to that pinned IP (sending the original
hostname as Host: header) so a DNS rebinding attack between validation
and scan time cannot redirect the scanner to a private/internal address.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

# RFC 1918 + loopback + link-local + multicast + reserved
BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),   # CGN
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]

# Dangerous hostnames
BLOCKED_HOSTNAMES = {
    "localhost", "localhost.localdomain",
    "metadata.google.internal",        # GCP metadata
    "169.254.169.254",                 # AWS/GCP/Azure metadata
    "metadata", "kubernetes", "kubernetes.default",
}

DOMAIN_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)


class TargetValidationError(Exception):
    """Raised when a scan target fails safety validation."""
    pass


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of validate_*: the cleaned target, plus the IP we resolved
    it to at validation time. The scanner must use `pinned_ip` for the
    actual TCP connection — re-resolving the hostname at scan time would
    open a DNS-rebinding TOCTOU window.

    `pinned_ip` is None for CIDR ranges (where many IPs are involved) and
    for domains that didn't resolve at validation time.
    """
    target_value: str
    target_type: str  # "domain" | "ip" | "cidr"
    pinned_ip: Optional[str] = None



def validate_domain(domain: str) -> str:
    """Backwards-compatible wrapper. Returns just the cleaned domain.

    WARNING: Since validation is now async to prevent event loop blocking,
    this synchronous wrapper does NOT pin the IP. Use `await validate_domain_pinned(domain)`
    instead whenever possible.
    """
    domain = domain.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).hostname or domain
    domain = domain.rstrip("/").rstrip(".")
    if domain in BLOCKED_HOSTNAMES:
        raise TargetValidationError(f"Blocked hostname: {domain}")
    if not DOMAIN_REGEX.match(domain):
        raise TargetValidationError(f"Invalid domain format: {domain}")
    return domain

async def _resolve_first_public_ip(domain: str) -> Optional[str]:
    """Resolve `domain` and return the first public IP. Raise if any answer
    is private/blocked — the caller must reject the target outright."""
    loop = asyncio.get_running_loop()
    try:
        answers = await loop.getaddrinfo(domain, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    public: list[str] = []
    for _, _, _, _, sockaddr in answers:
        ip = ipaddress.ip_address(sockaddr[0])
        if _is_private_ip(ip):
            raise TargetValidationError(
                f"Domain {domain} resolves to private IP {ip} — SSRF blocked"
            )
        public.append(str(ip))
    return public[0] if public else None

async def validate_domain_pinned(domain: str) -> ValidationResult:
    """Validate a domain and pin the resolved IP for scanner use."""
    domain = domain.strip().lower()

    # Strip protocol if accidentally included
    if "://" in domain:
        domain = urlparse(domain).hostname or domain

    # Strip trailing dot and slash
    domain = domain.rstrip("/").rstrip(".")

    if domain in BLOCKED_HOSTNAMES:
        raise TargetValidationError(f"Blocked hostname: {domain}")

    if not DOMAIN_REGEX.match(domain):
        raise TargetValidationError(
            f"Invalid domain format: {domain}. Expected format: example.com"
        )

    try:
        pinned_ip = await _resolve_first_public_ip(domain)
    except TargetValidationError:
        raise
    except Exception as exc:
        raise TargetValidationError(
            f"DNS resolution failed for {domain}: {exc}"
        )

    if not pinned_ip:
        raise TargetValidationError(
            f"Could not resolve domain to a valid public IP: {domain}"
        )

    return ValidationResult(target_value=domain, target_type="domain", pinned_ip=pinned_ip)



def validate_ip(ip_str: str) -> str:
    """Backwards-compatible wrapper around validate_ip_pinned."""
    return validate_ip_pinned(ip_str).target_value


def validate_ip_pinned(ip_str: str) -> ValidationResult:
    """Validate an IP address. The pinned IP equals the validated value."""
    ip_str = ip_str.strip()
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        raise TargetValidationError(f"Invalid IP address: {ip_str}")

    if _is_private_ip(ip):
        raise TargetValidationError(
            f"Private/reserved IP blocked: {ip_str}. Only public IPs allowed."
        )
    cleaned = str(ip)
    return ValidationResult(target_value=cleaned, target_type="ip", pinned_ip=cleaned)


def validate_cidr(cidr_str: str) -> str:
    """Backwards-compatible wrapper around validate_cidr_pinned."""
    return validate_cidr_pinned(cidr_str).target_value


def validate_cidr_pinned(cidr_str: str) -> ValidationResult:
    """Validate a CIDR range. CIDRs cover many hosts so no single IP is pinned."""
    cidr_str = cidr_str.strip()
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
    except ValueError:
        raise TargetValidationError(f"Invalid CIDR range: {cidr_str}")

    # Block oversized scans (max /16 = 65536 hosts)
    if network.prefixlen < 16:
        raise TargetValidationError(
            f"CIDR range too large: {cidr_str} ({network.num_addresses} hosts). Maximum allowed: /16"
        )

    # Check if range overlaps private networks
    for blocked in BLOCKED_NETWORKS:
        if network.overlaps(blocked):
            raise TargetValidationError(
                f"CIDR range {cidr_str} overlaps private/reserved network {blocked} — SSRF blocked"
            )
    return ValidationResult(target_value=str(network), target_type="cidr", pinned_ip=None)


def validate_target(target_type: str, target_value: str) -> str:
    """Backwards-compatible wrapper. Returns just the cleaned value."""
    # This is only safe for non-domain targets or if you don't care about the pin
    if target_type == "domain":
        return validate_domain(target_value)
    elif target_type == "ip":
        return validate_ip(target_value)
    elif target_type == "cidr":
        return validate_cidr(target_value)
    raise TargetValidationError(f"Unknown target type: {target_type}")


async def validate_target_pinned(target_type: str, target_value: str) -> ValidationResult:
    """Validate any target type and return both the cleaned value and the pinned IP."""
    if target_type == "domain":
        return await validate_domain_pinned(target_value)
    elif target_type == "ip":
        return validate_ip_pinned(target_value)
    elif target_type == "cidr":
        return validate_cidr_pinned(target_value)

    raise TargetValidationError(f"Unknown target type: {target_type}")


def _is_private_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if IP is in any blocked network."""
    for net in BLOCKED_NETWORKS:
        if ip in net:
            return True
    return False


async def validate_url_against_ssrf(url_str: str) -> None:
    """Validate a URL's host against private IP ranges and blocked domains to prevent SSRF."""
    if not url_str:
        raise TargetValidationError("Empty URL")
    
    parsed = urlparse(url_str)
    hostname = parsed.hostname
    if not hostname:
        raise TargetValidationError(f"Invalid URL (no hostname): {url_str}")
        
    try:
        ipaddress.ip_address(hostname)
        validate_ip_pinned(hostname)
    except ValueError:
        await validate_domain_pinned(hostname)

