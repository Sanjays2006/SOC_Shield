"""Reusable input-validation helpers."""

import ipaddress


def is_valid_ip(value):
    """Return True only for a syntactically valid IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def clamp_pagination(page, limit, default_limit=50, max_limit=200):
    """Normalize page/limit query params into safe integers.

    Returns (page, limit, skip) with page>=1 and 1<=limit<=max_limit.
    """
    try:
        page = max(1, int(page))
    except (TypeError, ValueError):
        page = 1
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = default_limit
    limit = max(1, min(limit, max_limit))
    skip = (page - 1) * limit
    return page, limit, skip
