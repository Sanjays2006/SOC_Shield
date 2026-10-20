"""
Automated response actions: Telegram notifications and firewall blocking.

Both actions are config-gated and safe to call unconditionally — they
no-op when disabled or misconfigured.
"""

import threading
import subprocess

import requests

from config import config
from services.validation import is_valid_ip


def send_telegram(msg):
    """Fire-and-forget Telegram message. No-op when not configured."""
    if not config.telegram_enabled():
        return

    def task():
        try:
            url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
            requests.post(
                url,
                data={"chat_id": config.TELEGRAM_CHAT_ID, "text": msg},
                timeout=2,
            )
        except Exception:
            pass

    threading.Thread(target=task, daemon=True).start()


def firewall_block_ip(ip):
    """Add a Windows Firewall block rule for a validated IP.

    Guarded by ENABLE_AUTO_BLOCK so it never runs in an unauthorized
    environment. Uses an argument list (no shell=True) so the IP cannot
    be abused for command injection.
    """
    if not config.ENABLE_AUTO_BLOCK:
        print(f"ℹ️ Auto-block disabled; skipping firewall rule for {ip}")
        return False
    if not is_valid_ip(ip):
        print(f"⚠️ Refusing to block invalid IP: {ip!r}")
        return False
    try:
        print(f"🚫 Blocking IP: {ip}")
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=Block_{ip}", "dir=in", "action=block",
             f"remoteip={ip}"],
            shell=False,
            check=False,
        )
        return True
    except Exception as e:
        print("Firewall error:", e)
        return False
