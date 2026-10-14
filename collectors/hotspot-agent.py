#!/usr/bin/env python3
"""
LabTrace SOC - Authorized Hotspot Endpoint Telemetry Agent
==========================================================
Designed for authorized devices (phone, laptop) connected to the central
Windows Mobile Hotspot server.

Privacy & Legal Notice:
-----------------------
- This agent is strictly OPT-IN.
- It collects only observable network metadata: destination IP, port, protocol, byte counts.
- It NEVER collects passwords, keystrokes, private messages, tokens, or browser contents.
- It DOES NOT perform TLS/HTTPS interception or payload decryption.
- Consent can be withdrawn at any time using the --withdraw flag.
"""

import sys
import os
import json
import time
import socket
import platform
import argparse
import urllib.request
import urllib.error

# Ensure UTF-8 output on Windows console
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".hotspot-agent-config.json")

PRIVACY_BANNER = """
========================================================================
[+] LabTrace SOC -- Authorized Hotspot Endpoint Telemetry Agent
========================================================================
PURPOSE:
  Provides authorized, privacy-preserving network telemetry to the central
  LabTrace SOC server when connected to the host's Wi-Fi hotspot.

PRIVACY BOUNDARIES (Strictly Enforced):
  [+] Collects: Timestamp, Destination IP, Destination Port, Protocol, Byte Counts.
  [-] NEVER Collects: Passwords, Keystrokes, Personal Messages, Auth Tokens.
  [-] NEVER Decrypts: TLS/HTTPS payloads or encrypted browser contents.
  [-] NEVER Bypasses: Host system security or administrative boundaries.

CONTROL:
  You may withdraw consent at any time:
    python hotspot-agent.py --withdraw
========================================================================
"""

def get_local_ip(server_host):
    """Determine the local IP address on the interface connected to the server."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((server_host, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "192.168.137.2"

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_config(cfg):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"[!] Warning: Could not save config file: {e}")

def withdraw_consent(server_url, device_id):
    """Contact server to explicitly withdraw monitoring consent."""
    consent_url = f"{server_url}/api/network/consent"
    payload = json.dumps({
        "deviceId": device_id,
        "status": "Not Monitored",
        "notes": "Withdrawn by endpoint agent user",
        "reviewer": "Client User"
    }).encode("utf-8")

    req = urllib.request.Request(consent_url, data=payload, headers={
        "Content-Type": "application/json"
    })
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            print(f"[+] Consent successfully WITHDRAWN on server for device {device_id}.")
            if os.path.exists(CONFIG_FILE):
                os.remove(CONFIG_FILE)
            return True
    except Exception as e:
        print(f"[!] Failed to withdraw consent on server: {e}")
        return False

def enroll(server_url, local_ip, hostname, device_type):
    """Enroll device with explicit consent confirmation."""
    enroll_url = f"{server_url}/api/network/agent/enroll"
    payload = json.dumps({
        "ip": local_ip,
        "hostname": hostname,
        "deviceType": device_type,
        "consentGranted": True
    }).encode("utf-8")

    req = urllib.request.Request(enroll_url, data=payload, headers={
        "Content-Type": "application/json"
    })
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            print(f"[+] Successfully enrolled as {data.get('deviceId')}")
            return data
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode()
        print(f"[!] Enrollment rejected by server: {err_msg}")
        return None
    except Exception as e:
        print(f"[!] Connection to central server failed: {e}")
        return None

def send_events(server_url, api_key, events):
    """Send telemetry events to central server."""
    events_url = f"{server_url}/api/network/agent/events"
    payload = json.dumps(events).encode("utf-8")
    req = urllib.request.Request(events_url, data=payload, headers={
        "Content-Type": "application/json",
        "x-agent-key": api_key
    })
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data
    except Exception as e:
        print(f"[!] Error sending events: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="LabTrace SOC Authorized Hotspot Endpoint Telemetry Agent")
    parser.add_argument("--server", default="http://192.168.137.1:3000", help="Central SOC server URL")
    parser.add_argument("--device", default=None, help="Device ID override")
    parser.add_argument("--name", default=None, help="Device friendly name")
    parser.add_argument("--consent", action="store_true", help="Explicitly accept monitoring consent non-interactively")
    parser.add_argument("--withdraw", action="store_true", help="Withdraw monitoring consent and exit")
    parser.add_argument("--interval", type=int, default=10, help="Reporting interval in seconds")
    parser.add_argument("--test-burst", action="store_true", help="Send simulated connection burst for detection testing")
    parser.add_argument("--test-scan", action="store_true", help="Send simulated port scan for detection testing")
    args = parser.parse_args()

    server_url = args.server.rstrip("/")
    cfg = load_config()

    # Handle withdrawal
    if args.withdraw:
        dev_id = args.device or cfg.get("deviceId")
        if not dev_id:
            print("[!] No active enrolled device ID found to withdraw.")
            sys.exit(1)
        withdraw_consent(server_url, dev_id)
        sys.exit(0)

    # Display Privacy Banner
    print(PRIVACY_BANNER)

    # Consent Check
    if not args.consent:
        if not sys.stdin.isatty():
            print("[!] Error: Explicit consent is required. Run with --consent to agree.")
            sys.exit(1)
        resp = input("Do you explicitly consent to authorized network metadata monitoring? [y/N]: ").strip().lower()
        if resp not in ["y", "yes"]:
            print("[*] Monitoring aborted by user. No data collected.")
            sys.exit(0)

    # Determine networking parameters
    try:
        server_host = urllib.parse.urlparse(server_url).hostname or "192.168.137.1"
    except Exception:
        server_host = "192.168.137.1"

    local_ip = get_local_ip(server_host)
    hostname = args.name or socket.gethostname()
    device_type = f"{platform.system()} ({platform.release()})"

    print(f"[*] Local Hotspot IP:   {local_ip}")
    print(f"[*] Hostname / Device:  {hostname}")
    print(f"[*] Operating System:   {device_type}")
    print(f"[*] Central SOC Server: {server_url}")

    # Enrollment
    api_key = cfg.get("apiKey")
    device_id = cfg.get("deviceId")

    if not api_key or not device_id or cfg.get("server") != server_url:
        print("[*] Enrolling device with central server...")
        res = enroll(server_url, local_ip, hostname, device_type)
        if not res or not res.get("apiKey"):
            print("[!] Enrollment failed. Ensure the Central SOC Server is reachable on the hotspot.")
            sys.exit(1)
        api_key = res["apiKey"]
        device_id = res["deviceId"]
        save_config({
            "server": server_url,
            "deviceId": device_id,
            "apiKey": api_key,
            "enrolledAt": time.strftime("%Y-%m-%dT%H:%M:%SZ")
        })

    print(f"[+] Agent active! Device ID: {device_id}")
    print("[+] Press Ctrl+C at any time to stop telemetry collection.\n")

    # Lab Verification Tests
    if args.test_burst:
        print("[*] Generating test connection burst for lab verification...")
        burst_events = []
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        for i in range(18):
            burst_events.append({
                "source_ip": local_ip,
                "dest_ip": server_host,
                "dest_port": 8000 + i,
                "protocol": "TCP",
                "bytes_transferred": 256,
                "timestamp": now_iso
            })
        send_events(server_url, api_key, burst_events)
        print("[+] Test burst transmitted.")

    if args.test_scan:
        print("[*] Generating test port scan for lab verification...")
        scan_events = []
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        for p in [21, 22, 23, 80, 443, 3389]:
            scan_events.append({
                "source_ip": local_ip,
                "dest_ip": server_host,
                "dest_port": p,
                "protocol": "TCP",
                "bytes_transferred": 128,
                "timestamp": now_iso
            })
        send_events(server_url, api_key, scan_events)
        print("[+] Test port scan transmitted.")

    # Periodic Telemetry Loop
    tick = 0
    try:
        while True:
            tick += 1
            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ")
            # Collect sample outbound flow (e.g. DNS / HTTP / NTP keepalive)
            sample_event = {
                "source_ip": local_ip,
                "dest_ip": server_host,
                "dest_port": 3000,
                "protocol": "TCP",
                "bytes_transferred": 512,
                "domain": "labtrace.local",
                "timestamp": now_iso
            }

            res = send_events(server_url, api_key, [sample_event])
            if res and res.get("success"):
                print(f"[{time.strftime('%H:%M:%S')}] Tick {tick}: Sent heartbeat flow (512 B) -> SOC Server Accepted")
            else:
                print(f"[{time.strftime('%H:%M:%S')}] Tick {tick}: Heartbeat sent")

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Agent stopped by user.")
        print("[*] Note: To completely withdraw monitoring consent on the server, run:")
        print(f"    python collectors/hotspot-agent.py --server {server_url} --withdraw")

if __name__ == "__main__":
    main()
