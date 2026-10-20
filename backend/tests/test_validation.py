"""Tests for input validation helpers."""

from services.validation import is_valid_ip, clamp_pagination


def test_valid_ips():
    assert is_valid_ip("8.8.8.8")
    assert is_valid_ip("2001:4860:4860::8888")


def test_invalid_ips():
    assert not is_valid_ip("not.an.ip")
    assert not is_valid_ip("1.1.1.1; rm -rf /")
    assert not is_valid_ip(None)
    assert not is_valid_ip("999.999.999.999")


def test_pagination_clamps():
    assert clamp_pagination(0, 9999) == (1, 200, 0)
    assert clamp_pagination(3, 20) == (3, 20, 40)
    assert clamp_pagination("x", "y") == (1, 50, 0)
