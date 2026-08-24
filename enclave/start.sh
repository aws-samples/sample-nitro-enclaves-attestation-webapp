#!/bin/bash
set -e

# Set up environment variables
export HOME=/root
export PYTHONPATH=/app:/app/shared:$PYTHONPATH

# Configure networking
echo "Setting up enclave networking..."
ip addr add 127.0.0.1/32 dev lo
ip link set dev lo up

echo "Starting vsock HTTP proxy..."
cd /app
python3 /app/vsock-http-proxy.py 8000 8001 &
PROXY_PID=$!

echo "Waiting for proxy to start..."
sleep 3

echo "Starting attestation API..."
exec python3 -m uvicorn main:app --host 127.0.0.1 --port 8001