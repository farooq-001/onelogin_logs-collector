#!/bin/bash

echo "🔐 Setting up OneLogin Filebeat Collector..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if docker-compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ docker-compose is not installed. Please install it first."
    exit 1
fi

# Create required directories
mkdir -p /opt/docker/onelogin/registry

# Write docker-compose.yml
cat <<EOF > /opt/docker/onelogin/docker-compose.yml
version: '3.7'

services:
  blu_onelogin:
    image: docker.elastic.co/beats/filebeat:6.8.7
    container_name: blu_onelogin
    network_mode: host
    volumes:
      - /opt/docker:/opt/docker
      - /opt/docker/onelogin/onelogin.yaml:/usr/share/filebeat/filebeat.yml
      - /opt/docker/onelogin/registry:/opt/docker/onelogin/registry
    environment:
      - BEAT_PATH=/usr/share/filebeat
    user: root
    restart: always
EOF

# Write onelogin.yaml config
cat <<EOF > /opt/docker/onelogin/onelogin.yaml
##################### Filebeat Configuration - OneLogin #########################

#======================= Filebeat Inputs =============================
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - "/opt/onelogin/onelogin_siem_logs.json"
    close_inactive: 10s
    scan_frequency: 60s
    fields:
      log.type: "onelogin"
    fields_under_root: true

#================== Filebeat Global Options ===============================
filebeat.registry.path: /opt/docker/onelogin/registry/onelogin

#========================= Filebeat Modules ===============================
filebeat.config.modules:
  path: "\${path.config}/modules.d/*.yml"
  reload.enabled: true
  reload.period: 60s

#========================= Logstash Output ===============================
output.logstash:
  hosts: ["127.0.0.1:12154"]
  loadbalance: true
  worker: 5
  bulk_max_size: 8192

#output.file:
#  enabled: true
#  path: "/opt/onelogin"
#  filename: "test.log"
#  rotate_every_kb: 10000
#  number_of_files: 7

#============================= Logging ====================================
logging.level: info
logging.to_files: true
logging.metrics.enabled: true
logging.metrics.period: 60s
logging.files:
  path: /var/log/filebeat/
  name: onelogin
  keepfiles: 7

#============================= Queue Settings ============================
queue.mem:
  events: 4096
  flush.min_events: 512
  flush.timeout: 1s
EOF

# Secure config file
chmod 600 /opt/docker/onelogin/onelogin.yaml

echo ""
echo "✅ OneLogin Filebeat setup completed."
echo "🚀 You can now start the container using:"
echo "   sudo docker-compose -f /opt/docker/onelogin/docker-compose.yml up -d"
