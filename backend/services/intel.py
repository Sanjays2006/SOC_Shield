"""Geo-location and IP intelligence lookups (ip-api.com)."""

import requests

from config import config
from services.validation import is_valid_ip


def get_geo(ip):
    """Return {country, lat, lon} for an IP, or {} on any failure."""
    if not is_valid_ip(ip):
        return {}
    try:
        res = requests.get(f"{config.IP_API_BASE}/{ip}", timeout=2).json()
        if res.get("status") != "success":
            return {}
        return {
            "country": res.get("country"),
            "lat": res.get("lat"),
            "lon": res.get("lon"),
        }
    except Exception:
        return {}


def lookup_ip(ip):
    """Full intel record for an IP. Raises on network error."""
    res = requests.get(f"{config.IP_API_BASE}/{ip}", timeout=5).json()
    return {
        "ip": ip,
        "country": res.get("country"),
        "city": res.get("city"),
        "isp": res.get("isp"),
        "org": res.get("org"),
        "lat": res.get("lat"),
        "lon": res.get("lon"),
        "status": res.get("status"),
    }
