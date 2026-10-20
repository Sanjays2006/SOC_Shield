"""
SOCShield agent.

Reads Suricata alerts from a file (Windows eve.json or system eve.json)
or generates a realistic simulation stream, then forwards each alert to
the backend /ingest endpoint.

Configuration via environment variables (optional):
  SOCSHIELD_SERVER   backend ingest URL (default http://127.0.0.1:5000/ingest)
  SOCSHIELD_WIN_LOG  path to the Windows eve.json file
  SOCSHIELD_SYS_LOG  path to the system eve.json file
"""

import time
import json
import os
import random
import uuid
from datetime import datetime, timezone

import requests

SERVER_URL = os.getenv("SOCSHIELD_SERVER", "http://127.0.0.1:5000/ingest")
INGEST_API_KEY = os.getenv("SOCSHIELD_API_KEY", "")

# 📂 Paths (override via env; defaults match the original layout)
WINDOWS_LOG = os.getenv(
    "SOCSHIELD_WIN_LOG",
    "/mnt/c/Users/INFANT AKASH W/Desktop/SOCShield/suricata_logs/eve.json",
)
SYSTEM_LOG = os.getenv("SOCSHIELD_SYS_LOG", "/var/log/suricata/eve.json")

last_position = 0


# ==============================
# 📂 COMMON FILE READER
# ==============================
def read_file_logs(path):
    global last_position
    print(f"📂 Reading logs from: {path}")

    while True:
        try:
            if not os.path.exists(path):
                print("❌ File not found:", path)
                time.sleep(3)
                continue

            with open(path, "r") as f:
                f.seek(last_position)
                lines = f.readlines()
                last_position = f.tell()

                for line in lines:
                    try:
                        log = json.loads(line.strip())
                        if log.get("event_type") == "alert":
                            yield log
                    except Exception:
                        continue

        except Exception as e:
            print("❌ Read error:", e)

        time.sleep(1)


def read_windows_logs():
    return read_file_logs(WINDOWS_LOG)


def read_system_logs():
    return read_file_logs(SYSTEM_LOG)


# ==============================
# 🟡 SIMULATION (realistic multi-field EVE-style events)
# ==============================
IPS = [
    "8.8.8.8", "1.1.1.1", "185.199.108.153",
    "45.33.32.156", "139.130.4.5", "103.21.244.0",
]

# (signature, example url, suricata_severity 1=high..3=low, typical dest_port, app_proto)
ATTACKS = [
    ("Low Level Scan",            "home",                       3, 80,   "http"),
    ("Medium Suspicious Activity", "login",                      2, 443,  "tls"),
    ("XSS Attack",                "<script>alert(1)</script>",  1, 80,   "http"),
    ("SQL Injection",             "id=1 UNION SELECT",          1, 3306, "mysql"),
    ("Brute Force Login",         "POST /login",                2, 22,   "ssh"),
    ("DDoS Attempt",              "flood",                      1, 80,   "http"),
    ("Critical Exploit Attempt",  "rm -rf /",                   1, 445,  None),
    ("Port Scan",                 "scan",                       2, 0,    None),
    ("Malware Drop",              "download.exe",               1, 8080, "http"),
]


def _eve_timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f%z")


def simulate_logs():
    while True:
        signature, url, severity, dport, app_proto = random.choice(ATTACKS)
        proto = "UDP" if signature == "DDoS Attempt" and random.random() < 0.3 else "TCP"

        # Flow volumes correlate loosely with attack type (DDoS/scan heavier).
        base = 50_000 if signature in ("DDoS Attempt", "Port Scan") else 1_500
        bytes_to_srv = random.randint(base, base * 10)
        bytes_to_cli = random.randint(100, max(200, base))
        pkts_to_srv = random.randint(5, 500 if base > 10_000 else 50)
        pkts_to_cli = random.randint(1, 50)

        log = {
            "event_type": "alert",
            "timestamp": _eve_timestamp(),
            "flow_id": uuid.uuid4().int >> 96,
            "src_ip": random.choice(IPS),
            "dest_ip": f"10.0.0.{random.randint(2, 254)}",
            "src_port": random.randint(1024, 65535),
            "dest_port": dport,
            "proto": proto,
            "app_proto": app_proto,
            "alert": {"signature": signature, "severity": severity},
            "http": {"url": url, "method": "GET"},
            "flow": {
                "bytes_toserver": bytes_to_srv,
                "bytes_toclient": bytes_to_cli,
                "pkts_toserver": pkts_to_srv,
                "pkts_toclient": pkts_to_cli,
            },
        }
        yield log
        time.sleep(random.uniform(0.5, 2))


# ==============================
# 📤 SEND
# ==============================
def send_log(log):
    try:
        headers = {"X-API-Key": INGEST_API_KEY} if INGEST_API_KEY else {}
        r = requests.post(SERVER_URL, json=log, timeout=5, headers=headers)
        if r.status_code == 200:
            sig = log.get("alert", {}).get("signature")
            print(f"✅ {log.get('src_ip')} | {sig}")
        else:
            print("⚠️ Server error:", r.status_code)
    except requests.exceptions.Timeout:
        print("⏱ Backend timeout")
    except requests.exceptions.ConnectionError:
        print("❌ Backend not reachable")
    except Exception as e:
        print("❌ Error:", e)


# ==============================
# 🚀 MAIN
# ==============================
def main():
    print("\n🔥 SOCShield Agent")
    print("1. Windows eve.json (manual logs)")
    print("2. Simulation mode (realistic multi-field events)")
    print("3. REAL Suricata system logs (LIVE IDS)")

    choice = input("Select mode (1/2/3): ").strip()

    if choice == "1":
        print("📁 Mode 1: Windows file logs\n")
        source = read_windows_logs()
    elif choice == "2":
        print("🟡 Mode 2: Simulation\n")
        source = simulate_logs()
    elif choice == "3":
        print("🟢 Mode 3: REAL Suricata logs (LIVE)\n")
        source = read_system_logs()
    else:
        print("❌ Invalid choice")
        return

    for log in source:
        sig = log.get("alert", {}).get("signature")
        print(f"🚨 {sig} from {log.get('src_ip')}")
        send_log(log)


if __name__ == "__main__":
    main()
