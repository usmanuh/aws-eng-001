
import re

import dns.exception
import dns.resolver


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$"
)


class DomainValidationError(Exception):
    pass


class DNSLookupError(Exception):
    pass


class DomainNotFoundError(Exception):
    pass


def validate_domain(domain):
    domain = domain.strip().lower()

    if not DOMAIN_PATTERN.fullmatch(domain):
        raise DomainValidationError("Invalid domain name")

    return domain


def lookup_records(resolver, domain, record_type):
    try:
        return resolver.resolve(domain, record_type)

    except dns.resolver.NoAnswer:
        return None

    except dns.resolver.NXDOMAIN as exc:
        raise DomainNotFoundError(
            f"DNS name does not exist: {domain}"
        ) from exc

    except dns.exception.Timeout as exc:
        raise DNSLookupError(
            "DNS lookup timed out"
        ) from exc

    except dns.resolver.NoNameservers as exc:
        raise DNSLookupError(
            "DNS nameservers unavailable"
        ) from exc

    except dns.exception.DNSException as exc:
        raise DNSLookupError(
            "DNS lookup failed"
        ) from exc


def lookup_txt(resolver, domain):
    answers = lookup_records(resolver, domain, "TXT")

    if answers is None:
        return []

    return [
        b"".join(record.strings).decode(
            "utf-8",
            errors="replace"
        )
        for record in answers
    ]


def check_domain(domain):
    domain = validate_domain(domain)

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout = 3
    resolver.lifetime = 8

    # MX records
    mx_answers = lookup_records(resolver, domain, "MX")
    mx_records = []

    if mx_answers:
        mx_records = sorted(
            [
                {
                    "priority": int(record.preference),
                    "server": str(record.exchange).rstrip(".")
                }
                for record in mx_answers
            ],
            key=lambda record: record["priority"]
        )

    if (
        len(mx_records) == 1
        and mx_records[0]["server"] == ""
    ):
        mx = {
            "status": "info",
            "records": mx_records,
            "message": (
                "This domain publishes a null MX record, "
                "indicating that it does not accept email."
            ),
            "recommendation": (
                "If the domain should receive email, "
                "replace the null MX with the correct mail servers."
            )
        }

    elif mx_records:
        mx = {
            "status": "pass",
            "records": mx_records,
            "message": "Mail receiving servers were found.",
            "recommendation": (
                "Confirm these servers match your email provider."
            )
        }

    else:
        mx = {
            "status": "warning",
            "records": [],
            "message": "No MX records were found.",
            "recommendation": (
                "If this domain should receive email, "
                "check its MX configuration."
            )
        }

    # SPF records
    spf_records = [
        record
        for record in lookup_txt(resolver, domain)
        if record.lower().startswith("v=spf1")
    ]

    if len(spf_records) == 1:
        spf_record = spf_records[0]
        mechanisms = spf_record.split()[1:]

        allows_everyone = any(
            mechanism.lower() in ("+all", "all")
            for mechanism in mechanisms
        )

        if allows_everyone:
            spf = {
                "status": "fail",
                "records": spf_records,
                "message": (
                    "SPF allows any server to send email "
                    "for this domain."
                ),
                "recommendation": (
                    "Remove the +all mechanism and configure SPF "
                    "to authorise only legitimate sending services."
                )
            }

        else:
            spf = {
                "status": "pass",
                "records": spf_records,
                "message": "An SPF policy was found.",
                "recommendation": (
                    "Verify that the policy includes all legitimate "
                    "email sending services."
                )
            }

    elif len(spf_records) > 1:
        spf = {
            "status": "fail",
            "records": spf_records,
            "message": "Multiple SPF policies were found.",
            "recommendation": (
                "Publish a single SPF policy for this domain."
            )
        }

    else:
        spf = {
            "status": "warning",
            "records": [],
            "message": "No SPF policy was found.",
            "recommendation": (
                "Configure SPF if this domain sends email."
            )
        }

    # DMARC records
    try:
        dmarc_txt_records = lookup_txt(
            resolver,
            f"_dmarc.{domain}"
        )
    except DomainNotFoundError:
        dmarc_txt_records = []

    dmarc_records = [
        record
        for record in dmarc_txt_records
        if record.lower().startswith("v=dmarc1")
    ]

    if len(dmarc_records) > 1:
        dmarc = {
            "status": "fail",
            "records": dmarc_records,
            "message": "Multiple DMARC policies were found.",
            "recommendation": (
                "Publish a single valid DMARC policy."
            )
        }

    elif len(dmarc_records) == 1:
        record = dmarc_records[0]

        tags = [
            tag.strip()
            for tag in record.split(";")
            if tag.strip()
        ]

        policy_tags = [
            tag.split("=", 1)[1].strip().lower()
            for tag in tags
            if "=" in tag
            and tag.split("=", 1)[0].strip().lower() == "p"
        ]

        if (
            len(policy_tags) != 1
            or policy_tags[0] not in (
                "none",
                "quarantine",
                "reject"
            )
        ):
            dmarc = {
                "status": "warning",
                "records": dmarc_records,
                "message": "DMARC policy requires review.",
                "recommendation": (
                    "Ensure the DMARC record contains exactly one "
                    "valid p= policy: none, quarantine or reject."
                )
            }

        else:
            policy = policy_tags[0]

            dmarc = {
                "status": (
                    "pass" if policy != "none" else "info"
                ),
                "records": dmarc_records,
                "policy": policy,
                "message": (
                    f"DMARC policy is set to {policy}."
                ),
                "recommendation": (
                    "Review DMARC reports and authentication "
                    "alignment before changing enforcement."
                )
            }

    else:
        dmarc = {
            "status": "warning",
            "records": [],
            "message": "No DMARC policy was found.",
            "recommendation": (
                "Consider publishing a DMARC policy, "
                "starting with monitoring."
            )
        }

    return {
        "domain": domain,
        "mx": mx,
        "spf": spf,
        "dmarc": dmarc
    }
