#!/bin/bash
# CodeDeploy ApplicationStart Hook
# Starts the application services

set -e

echo "=========================================="
echo "ApplicationStart: Starting services"
echo "=========================================="

cd /opt/nitro-attestation

# Verify EIF exists
if [ ! -f attestation-enclave.eif ]; then
    echo "ERROR: attestation-enclave.eif not found!"
    exit 1
fi

# Ensure Docker is running
echo "Ensuring Docker is running..."
systemctl start docker || true
sleep 2

# Resource requirements for the enclave (must match metadata.json)
ENCLAVE_CPU=$(jq -r '.cpu_count // 1' metadata.json 2>/dev/null || echo 1)
ENCLAVE_MEM=$(jq -r '.memory_mib // 2048' metadata.json 2>/dev/null || echo 2048)

# Reset the Nitro Enclaves allocator so hugepages/CPUs are reclaimed from any
# prior enclave. Repeated in-place deployments can leave the allocator in a
# state where a freshly launched enclave starts and then immediately
# terminates; a clean allocator before each attempt avoids that.
reset_allocator() {
    nitro-cli terminate-enclave --all >/dev/null 2>&1 || true
    sleep 2
    systemctl reset-failed nitro-enclaves-allocator.service 2>/dev/null || true
    systemctl restart nitro-enclaves-allocator.service 2>/dev/null || true
    sleep 3
}

# Start the enclave and confirm it reaches RUNNING and *stays* there. A start
# that dies within a few seconds is treated as a failure, not a success, so a
# flaky boot cannot be mistaken for a healthy deployment.
start_enclave_once() {
    systemctl start enclave-launcher.service

    local waited=0
    local max_wait=60
    local state="NONE"
    while [ $waited -lt $max_wait ]; do
        state=$(nitro-cli describe-enclaves 2>/dev/null | jq -r '.[0].State // "NONE"')
        if [ "$state" == "RUNNING" ]; then
            # Confirm the enclave is still running a few seconds later
            # (guards against the start-then-terminate failure mode).
            sleep 5
            state=$(nitro-cli describe-enclaves 2>/dev/null | jq -r '.[0].State // "NONE"')
            if [ "$state" == "RUNNING" ]; then
                echo "Enclave is running and stable"
                return 0
            fi
            echo "  Enclave left RUNNING state after starting (state=$state)"
            return 1
        fi
        sleep 2
        waited=$((waited + 2))
        echo "  Waiting for enclave... ($waited/$max_wait seconds, state=$state)"
    done
    echo "  Enclave did not reach RUNNING within $max_wait seconds (state=$state)"
    return 1
}

echo "Starting enclave (cpu=$ENCLAVE_CPU, mem=${ENCLAVE_MEM}MiB)..."
MAX_ATTEMPTS=3
ENCLAVE_OK=false
for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
    echo "Enclave start attempt $attempt/$MAX_ATTEMPTS"
    reset_allocator
    if start_enclave_once; then
        ENCLAVE_OK=true
        break
    fi
    echo "Attempt $attempt failed. Diagnostics:"
    nitro-cli describe-enclaves 2>/dev/null || true
    journalctl -u enclave-launcher.service --no-pager -n 40 2>/dev/null || true
    systemctl stop enclave-launcher.service 2>/dev/null || true
done

if [ "$ENCLAVE_OK" != "true" ]; then
    echo "ERROR: Enclave failed to start and stay running after $MAX_ATTEMPTS attempts"
    exit 1
fi

# Start proxy — listens on TCP :8000 (the NLB target) and forwards to the enclave
# over vsock. This is the only component on the parent in the request path; there is
# no application-layer backend proxy.
echo "Starting vsock proxy..."
systemctl start enclave-inbound-proxy.service
sleep 2

# Show final status
echo ""
echo "=========================================="
echo "Service Status"
echo "=========================================="
systemctl status enclave-launcher.service --no-pager || true
systemctl status enclave-inbound-proxy.service --no-pager || true

echo ""
echo "Enclave Status:"
nitro-cli describe-enclaves

echo ""
echo "ApplicationStart complete"
