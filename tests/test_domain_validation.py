
import pytest

from app.services.dns_checker import (
    validate_domain,
    DomainValidationError,
)


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("google.com", "google.com"),
        ("EXAMPLE.COM", "example.com"),
        ("  example.co.uk  ", "example.co.uk"),
        ("mail.example.com", "mail.example.com"),
        ("my-business.co.uk", "my-business.co.uk"),
    ],
)
def test_valid_domains(domain, expected):
    assert validate_domain(domain) == expected


@pytest.mark.parametrize(
    "domain",
    [
        "not-a-valid-domain",
        "example",
        "https://example.com",
        "example.com/path",
        "example..com",
        "-example.com",
        "example-.com",
        "example.com:443",
        "localhost",
        "",
    ],
)
def test_invalid_domains(domain):
    with pytest.raises(DomainValidationError):
        validate_domain(domain)
