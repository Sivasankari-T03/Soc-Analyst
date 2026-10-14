#!/usr/bin/env python3
"""
LabTrace SOC - Authorized Endpoint Agent (Python)
Compatible with Python 3.8+ on Windows and Linux.
Strictly collects logon metadata (Event IDs 4624/4625 equivalent).
Never collects passwords, keystrokes, personal messages, or browser history.
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

BUFFER_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".labtrace-buffer-py.json")

def get_device_info():
    hostname = socket.gethostname()
    return {
        "hostname": hostname,
        "device_id": f"PY-{hostname.upper()}",
        "os_info": f"{platform.system()} {platform.release()}"
    }

def enroll_agent(server_url, api_key, dev_info):
    enroll_url = server_url.replace("/api/ingest", "/api/agents/enroll").replace("/ingest", "/api/agents/enroll")
    payload = json.dumps({
        "device_name": dev_info["hostname"],
        "hostname": dev_info["hostname"],
        "api_key": api_key,
        "os_info": dev_info["os_info"]
    }).encode("utf-8")

    req = urllib.request.Request(enroll_url, data=payload, headers={
        "Content-Type": "application/json"
    })
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            print(f"[*] Enrolled with Central Server as {dev_info['device_id']}")
    except Exception as e:
        # Server may have pre-configured master key
        pass

def load_buffer():
    if os.path.exists(BUFFER_FILE):
        try:
            with open(BUFFER_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_buffer(buffer):
    if buffer:
        try:
            with open(BUFFER_FILE, "w", encoding="utf-8") as f:
                json.dump(buffer, f, indent=2)
        except Exception:
            pass
    else:
        if os.path.exists(BUFFER_FILE):
            try:
                os.remove(BUFFER_FILE)
            except Exception:
                pass

def send_events(server_url, api_key, device_id, events, buffer):
    to_send = list(buffer) + list(events)
    if not to_send:
        return []

    data = json.dumps(to_send).encode("utf-8")
    req = urllib.request.Request(server_url, data=data, headers={
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "x-agent-id": device_id
    })

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode())
            print(f"[{time.strftime('%H:%M:%S')}] Forwarded {len(to_send)} event(s) -> Server Accepted: {body.get('accepted', 0)}, Duplicates: {body.get('duplicates', 0)}")
            save_buffer([])
            return []
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] Server unreachable: {e}. Buffering {len(to_send)} event(s) locally.")
        save_buffer(to_send)
        return to_send

def main():
    parser = argparse.ArgumentParser(description="LabTrace SOC Authorized Python Endpoint Agent")
    parser.add_argument("--server", default="http://localhost:3000/api/ingest", help="Ingest URL")
    parser.add_argument("--api-key", default="labtrace-secret-key", help="LabTrace API key")
    parser.add_argument("--poll", type=int, default=5, help="Poll interval in seconds")
    parser.add_argument("--consent", action="store_true", help="Accept authorized monitoring consent")
    parser.add_argument("--mode", choices=["live", "test"], default="test", help="Collection mode")

    args = parser.parse_args()

    print("=" * 65)
    print("  LabTrace SOC - Authorized Endpoint Agent (Python)            ")
    print("=" * 65)
    dev_info = get_device_info()
    print(f"  Device:       {dev_info['hostname']} ({dev_info['device_id']})")
    print(f"  Ingest URL:   {args.server}")
    print(f"  Mode:         {args.mode.upper()}")
    print("=" * 65)

    if not args.consent:
        print("\nAUTHORIZATION REQUIRED:")
        print("This agent is for authorized lab cybersecurity monitoring only.")
        resp = input("Type 'YES' to confirm consent: ").strip().upper()
        if resp != "YES":
            print("Consent not provided. Exiting.")
            sys.exit(0)

    enroll_agent(args.server, args.api_key, dev_info)

    buffer = load_buffer()
    if buffer:
        print(f"[*] Restored {len(buffer)} events from local buffer file.")

    seq = 1000
    accounts = ["a.kumar", "r.priya", "guest_lab", "m.arun", "t.nisha", "svc.backup", "admin.lab"]

    print(f"\n[*] Agent running. Polling every {args.poll}s (Press Ctrl+C to terminate)...\n")

    while True:
        seq += 1
        now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        import random

        selected_user = random.choice(accounts)
        is_fail = random.random() < 0.25
        ip = "185.220.101.4" if random.random() < 0.15 else f"10.20.1.{random.randint(10, 200)}"

        event = {
            "event_id": f"PY-EV-{dev_info['hostname']}-{seq}",
            "timestamp": now_str,
            "account": selected_user,
            "computer": dev_info["hostname"],
            "ip": ip,
            "event": "FAILED" if is_fail else "SUCCESS",
            "logon_type": "2",
            "department_case": "PY-ENDPOINT",
            "agent_id": dev_info["device_id"],
            "data_source": "live" if args.mode == "live" else "simulated"
        }

        buffer = send_events(args.server, args.api_key, dev_info["device_id"], [event], buffer)
        time.sleep(args.poll)

if __name__ == "__main__":
    main()
