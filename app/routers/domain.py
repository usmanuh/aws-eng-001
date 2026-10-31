
import logging
import time

from fastapi import APIRouter, HTTPException, Request
from app.limiter import limiter

from app.services.dns_checker import (
    check_domain,
    DomainValidationError,
    DomainNotFoundError,
    DNSLookupError,
)

router = APIRouter()
logger = logging.getLogger("uvicorn.error")

@router.get("/check")
@limiter.limit("10/minute")
def domain_check(request: Request, domain: str):
    start_time = time.monotonic()

    try:
        result = check_domain(domain)

        logger.info(
            "Domain check completed duration_ms=%.0f",
            (time.monotonic() - start_time) * 1000,
        )

        return result

    except DomainValidationError as exc:
        logger.warning("Domain check rejected: invalid input")
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except DomainNotFoundError as exc:
        logger.info("Domain check completed: DNS name not found")
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except DNSLookupError as exc:
        logger.warning(
            "Domain check failed: DNS lookup error duration_ms=%.0f",
            (time.monotonic() - start_time) * 1000,
        )
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from exc
