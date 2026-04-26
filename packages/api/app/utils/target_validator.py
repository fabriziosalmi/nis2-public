# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
SSRF-safe target validation for scan assets.
Prevents scanning of internal/private IP ranges from the SaaS platform.
"""
import ipaddress
import re
import socket
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


def validate_domain(domain: str) -> str:
    """Validate a domain name for scanning. Returns cleaned domain."""
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

    # DNS resolution check — ensure it doesn't resolve to a private IP
    try:
        answers = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _, _, _, _, sockaddr in answers:
            ip = ipaddress.ip_address(sockaddr[0])
            if _is_private_ip(ip):
                raise TargetValidationError(
                    f"Domain {domain} resolves to private IP {ip} — SSRF blocked"
                )
    except socket.gaierror:
        pass  # Domain doesn't resolve yet — allow (scanner will handle)
    except TargetValidationError:
        raise
    except Exception:
        pass

    return domain


def validate_ip(ip_str: str) -> str:
    """Validate an IP address for scanning. Returns cleaned IP."""
    ip_str = ip_str.strip()
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        raise TargetValidationError(f"Invalid IP address: {ip_str}")

    if _is_private_ip(ip):
        raise TargetValidationError(
            f"Private/reserved IP blocked: {ip_str}. Only public IPs allowed."
        )
    return str(ip)


def validate_cidr(cidr_str: str) -> str:
    """Validate a CIDR range for scanning. Returns cleaned CIDR."""
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
    return str(network)


def validate_target(target_type: str, target_value: str) -> str:
    """Validate any target type. Returns cleaned value."""
    validators = {
        "domain": validate_domain,
        "ip": validate_ip,
        "cidr": validate_cidr,
    }
    validator = validators.get(target_type)
    if not validator:
        raise TargetValidationError(f"Unknown target type: {target_type}")
    return validator(target_value)


def _is_private_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if IP is in any blocked network."""
    for net in BLOCKED_NETWORKS:
        if ip in net:
            return True
    return False
