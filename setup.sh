#!/bin/bash

echo "🔐 FILL THE ONELOGIN-API KEYS:"

# Prompt for required values
read -p "Enter CLIENT_ID: " CLIENT_ID
read -p "Enter CLIENT_SECRET: " CLIENT_SECRET

# Display inputs
echo ""
echo "🔐 You Have Entered The Following ONELOGIN-API Keys:"
echo "CLIENT_ID     : $CLIENT_ID"
echo "CLIENT_SECRET : $CLIENT_SECRET"
echo ""

# Confirm installation
read -p "Proceed with installation? (y/n): " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "❌ Installation cancelled."
    exit 1
fi

# Ensure /opt/onelogin/ exists
INSTALL_DIR="/opt/onelogin"
rm -rf $INSTALL_DIR/onelogin_audit.old
mkdir -p "$INSTALL_DIR"
mv  $INSTALL_DIR/onelogin_audit.py  $INSTALL_DIR/onelogin_audit.old

# Create Python script inside /opt/onelogin/
cat <<EOF > $INSTALL_DIR/onelogin_audit.py
import requests
import json
import time
import os
import socket
from datetime import datetime, timedelta, timezone

# CONFIGURATION
CLIENT_ID = '${CLIENT_ID}'
CLIENT_SECRET = '${CLIENT_SECRET}'
BASE_URL = 'https://api.us.onelogin.com'
EVENTS_ENDPOINT = '/api/1/events'
SIEM_OUTPUT_FILE = 'onelogin_siem_logs.json'
REGISTRY_FILE = 'log_registry.json'
FETCH_INTERVAL_SECONDS = 30
UDP_HOST = '127.0.0.1'
UDP_PORT = 12514

def parse_timestamp(ts):
    try:
        return datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.strptime(ts, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)

def load_registry():
    if os.path.exists(REGISTRY_FILE):
        try:
            with open(REGISTRY_FILE, 'r') as f:
                content = f.read().strip()
                if not content:
                    return {}
                return json.loads(content)
        except Exception as e:
            print(f"⚠️ Failed to load registry: {e}")
            return {}
    return {}

def save_registry(data):
    with open(REGISTRY_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def get_access_token():
    url = f'{BASE_URL}/auth/oauth2/v2/token'
    headers = {'Content-Type': 'application/json'}
    payload = {
        'grant_type': 'client_credentials',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    r = requests.post(url, headers=headers, json=payload)
    r.raise_for_status()
    return r.json()['access_token']

def fetch_all_events(access_token, since=None, until=None):
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    events = []
    query_params = f'?since={since}&until={until}' if since and until else ''
    endpoint = f'{EVENTS_ENDPOINT}{query_params}'
    count = 1

    while True:
        print(f"📥 Fetching page {count}...")
        response = requests.get(f'{BASE_URL}{endpoint}', headers=headers)
        data = response.json()
        events.extend(data.get('data', []))

        next_link = data.get('pagination', {}).get('next_link')
        if not next_link:
            break
        endpoint = next_link.replace(BASE_URL, '')
        count += 1
        time.sleep(0.5)

    return events

def get_time_range(registry):
    now = datetime.now(timezone.utc)
    if 'last_event_timestamp' in registry:
        try:
            since = parse_timestamp(registry['last_event_timestamp'])
        except Exception:
            print("⚠️ Malformed timestamp in registry. Starting from now.")
            since = now
    else:
        since = now
    until = now
    return since.strftime('%Y-%m-%dT%H:%M:%SZ'), until.strftime('%Y-%m-%dT%H:%M:%SZ')

def filter_new_logs(logs, last_timestamp):
    if not last_timestamp:
        return logs
    last_dt = parse_timestamp(last_timestamp)
    return [log for log in logs if parse_timestamp(log['created_at']) > last_dt]

def write_log_entry(entry):
    with open(SIEM_OUTPUT_FILE, 'a') as f:
        f.write(json.dumps(entry) + '\n')

def send_udp_log(log):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        message = json.dumps(log).encode()
        sock.sendto(message, (UDP_HOST, UDP_PORT))
        print(f"📤 Sent log over UDP to {UDP_HOST}:{UDP_PORT} | ID: {log.get('id', 'N/A')}")
        sock.close()
    except Exception as e:
        print(f"⚠️ Failed to send UDP log: {e}")

def prune_old_logs():
    if not os.path.exists(SIEM_OUTPUT_FILE):
        return

    threshold = datetime.now(timezone.utc) - timedelta(days=5)
    new_lines = []

    with open(SIEM_OUTPUT_FILE, 'r') as f:
        for line in f:
            try:
                log = json.loads(line)
                ts = parse_timestamp(log.get('created_at', ''))
                if ts >= threshold:
                    new_lines.append(line)
            except:
                continue

    with open(SIEM_OUTPUT_FILE, 'w') as f:
        f.writelines(new_lines)

def run_fetcher():
    while True:
        registry = load_registry()
        try:
            print("\n==============================")
            print(f"🕒 Fetch started at {datetime.now().isoformat()}")
            token = get_access_token()

            since, until = get_time_range(registry)
            print(f"📅 Fetching logs from {since} to {until}...")
            all_logs = fetch_all_events(token, since, until)

            new_logs = filter_new_logs(all_logs, registry.get('last_event_timestamp'))

            if not new_logs:
                print("ℹ️ No new logs found.")
            else:
                print(f"🆕 {len(new_logs)} new logs found. Writing...")
                for log in new_logs:
                    write_log_entry(log)
                    send_udp_log(log)

            last_event_time = new_logs[-1]['created_at'] if new_logs else registry.get('last_event_timestamp', until)
            registry.update({
                'last_event_timestamp': last_event_time,
                'last_run_status': 'success',
                'total_events_fetched': len(new_logs),
                'last_error': ''
            })

            prune_old_logs()

        except Exception as e:
            print(f"❌ Error: {e}")
            registry.update({
                'last_run_status': 'failure',
                'last_error': str(e)
            })

        finally:
            save_registry(registry)
            print("📒 Registry updated.")
            print(f"⏳ Sleeping for {FETCH_INTERVAL_SECONDS} seconds...")
            time.sleep(FETCH_INTERVAL_SECONDS)

if __name__ == '__main__':
    run_fetcher()
EOF

# Make script executable
chmod +x "$INSTALL_DIR/onelogin_audit.py"

# Create systemd service
cat <<EOF > /etc/systemd/system/onelogin_audit.service
[Unit]
Description=OneLogin Audit Script
After=network.target

[Service]
ExecStart=/usr/bin/env python3 $INSTALL_DIR/onelogin_audit.py
Restart=always
RestartSec=5
User=root
WorkingDirectory=$INSTALL_DIR
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and start service
systemctl daemon-reload
systemctl enable onelogin_audit.service
systemctl start onelogin_audit.service

echo ""
echo "✅ OneLogin audit service installed and started."
echo "📂 Directory: $INSTALL_DIR"
echo "📁 Log file : $INSTALL_DIR/onelogin_siem_logs.json"
echo "📒 Registry : $INSTALL_DIR/log_registry.json"
