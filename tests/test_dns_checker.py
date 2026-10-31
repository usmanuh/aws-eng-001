
from unittest.mock import Mock, patch

import dns.exception
import dns.resolver
import pytest

from app.services.dns_checker import (
    check_domain,
    DomainNotFoundError,
    DNSLookupError,
)


def make_txt_record(value):
    record = Mock()
    record.strings = [value.encode("utf-8")]
    return record


def make_mx_record(priority, server):
    record = Mock()
    record.preference = priority
    record.exchange = server + "."
    return record


@patch("app.services.dns_checker.dns.resolver.Resolver")
def test_valid_domain_with_all_records(mock_resolver_class):
    resolver = mock_resolver_class.return_value

    def resolve(domain, record_type):
        if record_type == "MX":
            return [make_mx_record(10, "mail.example.com")]

        if domain == "example.com" and record_type == "TXT":
            return [make_txt_record("v=spf1 -all")]

        if domain == "_dmarc.example.com" and record_type == "TXT":
            return [make_txt_record("v=DMARC1; p=reject")]

        raise AssertionError("Unexpected DNS query")

    resolver.resolve.side_effect = resolve

    result = check_domain("example.com")

    assert result["mx"]["status"] == "pass"
    assert result["spf"]["status"] == "pass"
    assert result["dmarc"]["status"] == "pass"
    assert result["dmarc"]["policy"] == "reject"


@patch("app.services.dns_checker.dns.resolver.Resolver")
def test_nonexistent_domain(mock_resolver_class):
    resolver = mock_resolver_class.return_value
    resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

    with pytest.raises(DomainNotFoundError):
        check_domain("nonexistent-example.com")


@patch("app.services.dns_checker.dns.resolver.Resolver")
def test_missing_dmarc_record(mock_resolver_class):
    resolver = mock_resolver_class.return_value

    def resolve(domain, record_type):
        if domain == "_dmarc.example.com":
            raise dns.resolver.NXDOMAIN()

        if record_type == "MX":
            return [make_mx_record(10, "mail.example.com")]

        if record_type == "TXT":
            return [make_txt_record("v=spf1 -all")]

        raise AssertionError("Unexpected DNS query")

    resolver.resolve.side_effect = resolve

    result = check_domain("example.com")

    assert result["mx"]["status"] == "pass"
    assert result["spf"]["status"] == "pass"
    assert result["dmarc"]["status"] == "warning"
    assert result["dmarc"]["records"] == []


@patch("app.services.dns_checker.dns.resolver.Resolver")
def test_dns_timeout(mock_resolver_class):
    resolver = mock_resolver_class.return_value
    resolver.resolve.side_effect = dns.exception.Timeout()

    with pytest.raises(DNSLookupError, match="timed out"):
        check_domain("example.com")


@patch("app.services.dns_checker.dns.resolver.Resolver")
def test_missing_spf_record(mock_resolver_class):
    resolver = mock_resolver_class.return_value

    def resolve(domain, record_type):
        if record_type == "MX":
            return [make_mx_record(10, "mail.example.com")]

        if domain == "example.com" and record_type == "TXT":
            raise dns.resolver.NoAnswer()

        if domain == "_dmarc.example.com" and record_type == "TXT":
            return [make_txt_record("v=DMARC1; p=none")]

        raise AssertionError("Unexpected DNS query")

    resolver.resolve.side_effect = resolve

    result = check_domain("example.com")

    assert result["spf"]["status"] == "warning"
    assert result["dmarc"]["status"] == "info"
    assert result["dmarc"]["policy"] == "none"


from unittest.mock import patch


def test_spf_allow_all_is_flagged():
    from app.services.dns_checker import check_domain

    def mock_lookup(resolver, domain, record_type):
        if record_type == "MX":
            return None
        return None

    def mock_txt(resolver, domain):
        if domain.startswith("_dmarc."):
            return ["v=DMARC1; p=reject"]
        return ["v=spf1 +all"]

    with (
        patch(
            "app.services.dns_checker.lookup_records",
            side_effect=mock_lookup,
        ),
        patch(
            "app.services.dns_checker.lookup_txt",
            side_effect=mock_txt,
        ),
    ):
        result = check_domain("example.com")

    assert result["spf"]["status"] == "fail"


import pytest


@pytest.mark.parametrize(
    "spf_record, expected_status",
    [
        ("v=spf1 +all", "fail"),
        ("v=spf1 all", "fail"),
        ("v=spf1 ip4:192.0.2.1 +ALL", "fail"),
        ("v=spf1 -all", "pass"),
        ("v=spf1 ~all", "pass"),
        ("v=spf1 ?all", "pass"),
        ("v=spf1 include:_spf.example.com -all", "pass"),
    ],
)
def test_spf_all_mechanism_variations(spf_record, expected_status):
    from unittest.mock import patch
    from app.services.dns_checker import check_domain

    def mock_lookup(resolver, domain, record_type):
        return None

    def mock_txt(resolver, domain):
        if domain.startswith("_dmarc."):
            return ["v=DMARC1; p=reject"]
        return [spf_record]

    with (
        patch(
            "app.services.dns_checker.lookup_records",
            side_effect=mock_lookup,
        ),
        patch(
            "app.services.dns_checker.lookup_txt",
            side_effect=mock_txt,
        ),
    ):
        result = check_domain("example.com")

    assert result["spf"]["status"] == expected_status


@pytest.mark.parametrize(
    "dmarc_record",
    [
        "v=DMARC1; p=none; p=reject",
        "v=DMARC1; p=reject; p=none",
        "v=DMARC1; p=invalid",
        "v=DMARC1; p=",
    ],
)
def test_invalid_dmarc_policy_is_not_passed(dmarc_record):
    from unittest.mock import patch
    from app.services.dns_checker import check_domain

    def mock_lookup(resolver, domain, record_type):
        return None

    def mock_txt(resolver, domain):
        if domain.startswith("_dmarc."):
            return [dmarc_record]
        return ["v=spf1 -all"]

    with (
        patch(
            "app.services.dns_checker.lookup_records",
            side_effect=mock_lookup,
        ),
        patch(
            "app.services.dns_checker.lookup_txt",
            side_effect=mock_txt,
        ),
    ):
        result = check_domain("example.com")

    assert result["dmarc"]["status"] == "warning"
