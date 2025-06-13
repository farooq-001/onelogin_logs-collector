#!/usr/bin/env python3
import time
import requests
import socket
import json
import os
import sqlite3
import hashlib

CLIENT_ID = '${CLIENT_ID}'
CLIENT_SECRET = '${CLIENT_SECRET}'

TOKEN_URL = 'https://api.us.onelogin.com/auth/oauth2/v2/token'
USERS_URL = 'https://api.us.onelogin.com/api/2/users'

REMOTE_HOST = '${REMOTE_HOST}'
REMOTE_PORT = ${PORT}

INTERVAL = 30  # seconds
DB_FILE = '/opt/onelogin_state.db'


class OneLoginAPI:
    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self.token_expiry = 0

    def get_token(self):
        headers = {'Content-Type': 'application/json'}
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


class StateDB:
    def __init__(self, db_file):
        self.conn = sqlite3.connect(db_file)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS state (
                id INTEGER PRIMARY KEY,
                last_hash TEXT,
                last_sent_time TEXT
            )
        ''')
        if not self.get_last_hash():
            self.conn.execute("INSERT INTO state (last_hash, last_sent_time) VALUES (?, ?)", ('', ''))
            self.conn.commit()

    def get_last_hash(self):
        cur = self.conn.cursor()
        cur.execute("SELECT last_hash FROM state WHERE id=1")
        row = cur.fetchone()
        return row[0] if row else None

    def update_state(self, data_hash):
        self.conn.execute("UPDATE state SET last_hash=?, last_sent_time=datetime('now') WHERE id=1", (data_hash,))
        self.conn.commit()
        print("[INFO] State DB updated.")


def compute_hash(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode('utf-8')).hexdigest()


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
    db = StateDB(DB_FILE)

    while True:
        try:
            latest_data = onelogin.get_users()
            latest_hash = compute_hash(latest_data)
            last_hash = db.get_last_hash()

            if latest_hash != last_hash:
                print("[INFO] Changes detected, sending logs and updating DB.")
                send_logs_to_host(REMOTE_HOST, REMOTE_PORT, latest_data)
                db.update_state(latest_hash)
            else:
                print("[INFO] No changes in user data.")

        except Exception as e:
            print(f"[ERROR] {e}")

        time.sleep(INTERVAL)
