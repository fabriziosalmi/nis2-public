"""
Tests for the SSRF target validator.
Can run standalone without any database or API dependencies.
"""
import pytest
from app.utils.target_validator import (
    TargetValidationError,
    validate_cidr,
    validate_domain,
    validate_ip,
    validate_target,
)


class TestValidateDomain:
    def test_simple_domain(self):
        assert validate_domain("example.com") == "example.com"

    def test_subdomain(self):
        assert validate_domain("sub.example.com") == "sub.example.com"

    def test_strips_protocol(self):
        assert validate_domain("https://example.com/path") == "example.com"

    def test_strips_trailing_slash(self):
        assert validate_domain("example.com/") == "example.com"

    def test_strips_trailing_dot(self):
        assert validate_domain("example.com.") == "example.com"

    def test_case_insensitive(self):
        assert validate_domain("EXAMPLE.COM") == "example.com"

    def test_blocked_localhost(self):
        with pytest.raises(TargetValidationError, match="Blocked"):
            validate_domain("localhost")

    def test_blocked_metadata_google(self):
        with pytest.raises(TargetValidationError, match="Blocked"):
            validate_domain("metadata.google.internal")

    def test_blocked_metadata_ip(self):
        with pytest.raises(TargetValidationError, match="Blocked"):
            validate_domain("169.254.169.254")

    def test_invalid_format(self):
        with pytest.raises(TargetValidationError, match="Invalid domain"):
            validate_domain("not a domain!")

    def test_single_label(self):
        with pytest.raises(TargetValidationError):
            validate_domain("localhost-not-blocked")  # single label, no TLD


class TestValidateIP:
    def test_public_ipv4(self):
        assert validate_ip("8.8.8.8") == "8.8.8.8"

    def test_public_ipv4_cloudflare(self):
        assert validate_ip("1.1.1.1") == "1.1.1.1"

    def test_blocked_rfc1918_10(self):
        with pytest.raises(TargetValidationError, match="Private"):
            validate_ip("10.0.0.1")

    def test_blocked_rfc1918_172(self):
        with pytest.raises(TargetValidationError, match="Private"):
            validate_ip("172.16.0.1")

    def test_blocked_rfc1918_192(self):
        with pytest.raises(TargetValidationError, match="Private"):
            validate_ip("192.168.1.1")

    def test_blocked_loopback(self):
        with pytest.raises(TargetValidationError, match="Private"):
            validate_ip("127.0.0.1")

    def test_blocked_link_local(self):
        with pytest.raises(TargetValidationError, match="Private"):
            validate_ip("169.254.1.1")

    def test_blocked_cgn(self):
        with pytest.raises(TargetValidationError, match="Private"):
            validate_ip("100.64.0.1")

    def test_blocked_aws_metadata(self):
        with pytest.raises(TargetValidationError, match="Private"):
            validate_ip("169.254.169.254")

    def test_invalid_format(self):
        with pytest.raises(TargetValidationError, match="Invalid IP"):
            validate_ip("not-an-ip")

    def test_empty(self):
        with pytest.raises(TargetValidationError):
            validate_ip("")


class TestValidateCIDR:
    def test_valid_public(self):
        assert validate_cidr("203.0.113.0/24") == "203.0.113.0/24"

    def test_valid_slash_32(self):
        assert validate_cidr("8.8.8.8/32") == "8.8.8.8/32"

    def test_blocked_private(self):
        with pytest.raises(TargetValidationError, match="SSRF"):
            validate_cidr("192.168.0.0/16")

    def test_blocked_loopback(self):
        with pytest.raises(TargetValidationError, match="(SSRF|too large)"):
            validate_cidr("127.0.0.0/8")

    def test_too_large(self):
        with pytest.raises(TargetValidationError, match="too large"):
            validate_cidr("0.0.0.0/8")

    def test_max_allowed_size(self):
        # /16 = 65536 hosts — should pass if public
        assert validate_cidr("203.0.0.0/16") == "203.0.0.0/16"

    def test_invalid_format(self):
        with pytest.raises(TargetValidationError, match="Invalid CIDR"):
            validate_cidr("not-a-cidr")


class TestValidateTarget:
    def test_dispatch_domain(self):
        assert validate_target("domain", "example.com") == "example.com"

    def test_dispatch_ip(self):
        assert validate_target("ip", "8.8.8.8") == "8.8.8.8"

    def test_dispatch_cidr(self):
        assert validate_target("cidr", "203.0.113.0/24") == "203.0.113.0/24"

    def test_unknown_type(self):
        with pytest.raises(TargetValidationError, match="Unknown target type"):
            validate_target("unknown", "value")
