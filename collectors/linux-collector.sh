#!/usr/bin/env bash
# LabTrace Linux & Honeypot SSH Collector
# Streams /var/log/auth.log failed and successful SSH logins to LabTrace Ingest Server

SERVER_URL="${SERVER_URL:-http://localhost:3000/api/ingest}"
API_KEY="${API_KEY:-labtrace-secret-key}"
LOG_FILE="${LOG_FILE:-/var/log/auth.log}"

echo "=================================================="
echo "  LabTrace Linux & Honeypot Collector             "
echo "  Target Server: $SERVER_URL                      "
echo "  Monitoring:    $LOG_FILE                        "
echo "=================================================="

if [ ! -r "$LOG_FILE" ]; then
  echo "Error: Cannot read $LOG_FILE. Run with sudo or set proper permissions."
  exit 1
fi

tail -Fn0 "$LOG_FILE" | while read -r line; do
  # Pattern 1: Failed password for invalid user <user> from <ip>
  # Pattern 2: Failed password for <user> from <ip>
  # Pattern 3: Accepted password/publickey for <user> from <ip>

  if echo "$line" | grep -q "sshd.*Failed password"; then
    account=$(echo "$line" | grep -oP 'Failed password for (invalid user )?\K\S+')
    ip=$(echo "$line" | grep -oP 'from \K[0-9a-fA-F\.:]+')
    status="FAILED"
  elif echo "$line" | grep -q "sshd.*Accepted"; then
    account=$(echo "$line" | grep -oP 'Accepted (password|publickey) for \K\S+')
    ip=$(echo "$line" | grep -oP 'from \K[0-9a-fA-F\.:]+')
    status="SUCCESS"
  else
    continue
  fi

  if [ -n "$account" ] && [ -n "$ip" ]; then
    timestamp=$(date -u +"%Y-%m-%d %H:%M:%S")
    event_id="SSH-$(date +%s)-$RANDOM"
    hostname=$(hostname)

    payload=$(cat <<EOF
[
  {
    "event_id": "$event_id",
    "timestamp": "$timestamp",
    "account": "$account",
    "computer": "$hostname",
    "ip": "$ip",
    "event": "$status",
    "logon_type": "SSH",
    "department_case": "HONEYPOT-SSH"
  }
]
EOF
)

    curl -s -X POST "$SERVER_URL" \
      -H "Content-Type: application/json" \
      -H "x-api-key: $API_KEY" \
      -d "$payload" > /dev/null
    
    echo "[$(date +"%H:%M:%S")] Forwarded SSH $status: $account from $ip"
  fi
done
