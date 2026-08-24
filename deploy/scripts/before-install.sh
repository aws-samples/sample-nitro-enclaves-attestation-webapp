#!/bin/bash
# CodeDeploy BeforeInstall Hook
# Runs before the application files are copied

set -e

echo "=========================================="
echo "BeforeInstall: Preparing for deployment"
echo "=========================================="

# Stop services gracefully before deployment
echo "Stopping existing services..."
systemctl stop enclave-inbound-proxy.service 2>/dev/null || true

# Migration: tear down legacy units from the previous architecture if present —
# the parent FastAPI backend (bound :8000, now used by the inbound proxy) and the
# old service names (attestation-enclave/attestation-proxy, renamed to
# enclave-launcher/enclave-inbound-proxy) plus the unused frontend unit. Leaving the
# backend running would cause a port conflict. Safe/idempotent when already gone.
for legacy in attestation-backend attestation-enclave attestation-proxy attestation-frontend; do
    systemctl stop "$legacy.service" 2>/dev/null || true
    systemctl disable "$legacy.service" 2>/dev/null || true
    rm -f "/etc/systemd/system/$legacy.service" 2>/dev/null || true
done
docker rm -f attestation-backend 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true

# Terminate existing enclave
echo "Terminating existing enclave..."
nitro-cli terminate-enclave --all 2>/dev/null || true

# Clean up old deployment (but keep logs)
echo "Cleaning up old deployment..."
rm -rf /opt/nitro-attestation/backend 2>/dev/null || true
rm -rf /opt/nitro-attestation/proxies 2>/dev/null || true
rm -rf /opt/nitro-attestation/enclave 2>/dev/null || true
rm -f /opt/nitro-attestation/*.eif 2>/dev/null || true
rm -f /opt/nitro-attestation/metadata.json 2>/dev/null || true

# Create directories
echo "Creating deployment directories..."
mkdir -p /opt/nitro-attestation/{backend,proxies,enclave/shared,logs}
chown -R root:root /opt/nitro-attestation

echo "BeforeInstall complete"