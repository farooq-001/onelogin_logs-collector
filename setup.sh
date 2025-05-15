#!/bin/bash

echo "🔐 FILL THE ONELOGIN-API KEYS:"

# Prompt for required values
read -p "Enter CLIENT_ID: " CLIENT_ID
read -p "Enter CLIENT_SECRET: " CLIENT_SECRET
read -p "Enter REMOTE_HOST: " REMOTE_HOST
read -p "Enter PORT: " PORT

# Display inputs
echo ""
echo "You have entered the following:"
echo "CLIENT_ID     : $CLIENT_ID"
echo "CLIENT_SECRET : $CLIENT_SECRET"
echo "REMOTE_HOST   : $REMOTE_HOST"
echo "PORT          : $PORT"
echo ""

# Confirm installation
read -p "Proceed with installation? (y/n): " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "❌ Installation cancelled."
    exit 1
fi

# Create Python script
cat <<EOF > /opt/onelogin_audit.py
#!/usr/bin/env python3
import time
import requests
import socket
import json

CLIENT_ID = '${CLIENT_ID}'
CLIENT_SECRET = '${CLIENT_SECRET}'

TOKEN_URL = 'https://api.us.onelogin.com/auth/oauth2/v2/token'
USERS_URL = 'https://api.us.onelogin.com/api/2/users'

REMOTE_HOST = '${REMOTE_HOST}'
REMOTE_PORT = ${PORT}

INTERVAL = 30  # 30 seconds


class OneLoginAPI:
    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self.token_expiry = 0

    def get_token(self):
        headers = {
            'Content-Type': 'application/json',
        }
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }

        response = requests.post(TOKEN_URL, headers=headers, json=data)
        response.raise_for_status()
        token_data = response.json()

        self.access_token = token_data['access_token']
        self.token_expiry = time.time() + token_data['expires_in'] - 60
        print(f"[INFO] Obtained new token, expires in {token_data['expires_in']} seconds.")

    def ensure_token_valid(self):
        if not self.access_token or time.time() >= self.token_expiry:
            self.get_token()

    def get_users(self):
        self.ensure_token_valid()
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        response = requests.get(USERS_URL, headers=headers)
        response.raise_for_status()
        return response.json()


def send_logs_to_host(host, port, data):
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            json_data = json.dumps(data)
            sock.sendall(json_data.encode('utf-8'))
            print(f"[INFO] Sent logs to {host}:{port}")
    except Exception as e:
        print(f"[ERROR] Failed to send logs: {e}")


if __name__ == '__main__':
    onelogin = OneLoginAPI(CLIENT_ID, CLIENT_SECRET)

    while True:
        try:
            logs = onelogin.get_users()
            send_logs_to_host(REMOTE_HOST, REMOTE_PORT, logs)
        except Exception as e:
            print(f"[ERROR] {e}")

        time.sleep(INTERVAL)
EOF

# Ensure script is executable
chmod +x /opt/onelogin_audit.py

# Create systemd service file
cat <<EOF > /etc/systemd/system/onelogin_audit.service
[Unit]
Description=OneLogin Audit Script
After=network.target

[Service]
ExecStart=/usr/bin/env python3 /opt/onelogin_audit.py
Restart=always
RestartSec=5
User=root
WorkingDirectory=/opt
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd, enable and start service
systemctl daemon-reload
systemctl enable onelogin_audit.service
systemctl start onelogin_audit.service

echo "✅ OneLogin audit service installed and started."
