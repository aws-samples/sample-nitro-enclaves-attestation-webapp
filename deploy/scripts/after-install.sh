#!/bin/bash
# CodeDeploy AfterInstall Hook
# Runs after files are copied, before application starts

set -e

echo "=========================================="
echo "AfterInstall: Configuring deployment"
echo "=========================================="

cd /opt/nitro-attestation

# Configure nitro-enclaves allocator based on metadata
if [ -f metadata.json ]; then
    echo "Configuring nitro-enclaves allocator from metadata..."
    CPU_COUNT=$(jq -r ".cpu_count // 1" metadata.json)
    MEMORY_MIB=$(jq -r ".memory_mib // 2048" metadata.json)
    
    echo "  CPU Count: $CPU_COUNT"
    echo "  Memory MiB: $MEMORY_MIB"
    
    cat > /etc/nitro_enclaves/allocator.yaml << EOF
---
cpu_count: $CPU_COUNT
memory_mib: $MEMORY_MIB
EOF
    
    # Reset and restart allocator to apply new settings
    systemctl reset-failed nitro-enclaves-allocator.service 2>/dev/null || true
    systemctl restart nitro-enclaves-allocator.service 2>/dev/null || true
    sleep 2
else
    echo "WARNING: metadata.json not found, using default allocator settings"
fi

# Reload systemd to pick up any service file changes
echo "Reloading systemd daemon..."
systemctl daemon-reload

# Enable services (so they start on reboot)
echo "Enabling services..."
systemctl enable enclave-launcher.service
systemctl enable enclave-inbound-proxy.service

# Set correct permissions
echo "Setting permissions..."
chmod +x /opt/nitro-attestation/proxies/*.py 2>/dev/null || true
chmod 644 /opt/nitro-attestation/attestation-enclave.eif

echo "AfterInstall complete"
