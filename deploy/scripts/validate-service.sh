#!/bin/bash
# CodeDeploy ValidateService Hook
# Validates that the deployment was successful

set -e

echo "=========================================="
echo "ValidateService: Validating deployment"
echo "=========================================="

VALIDATION_PASSED=true

# Check 1: Enclave is running
echo "Checking enclave status..."
ENCLAVE_STATUS=$(nitro-cli describe-enclaves 2>/dev/null | jq -r '.[0].State // "NONE"')
if [ "$ENCLAVE_STATUS" == "RUNNING" ]; then
    echo "  ✓ Enclave is running"
else
    echo "  ✗ Enclave is NOT running (status: $ENCLAVE_STATUS)"
    VALIDATION_PASSED=false
fi

# Check 2: Proxy service is active
echo "Checking proxy service..."
if systemctl is-active --quiet enclave-inbound-proxy.service; then
    echo "  ✓ Proxy service is active"
else
    echo "  ✗ Proxy service is NOT active"
    VALIDATION_PASSED=false
fi

# Check 3: Health endpoint responds (via the proxy -> enclave on :8000)
echo "Checking health endpoint..."
HEALTH_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/health 2>/dev/null || echo "000")
if [ "$HEALTH_RESPONSE" == "200" ]; then
    echo "  ✓ Health endpoint returned 200"
else
    echo "  ✗ Health endpoint returned $HEALTH_RESPONSE (expected 200)"
    VALIDATION_PASSED=false
fi

# Check 5: Attestation endpoint responds
echo "Checking attestation endpoint..."
ATTEST_RESPONSE=$(curl -s -X POST http://localhost:8000/api/attestation \
    -H "Content-Type: application/json" \
    -d '{"nonce": "validation-test"}' 2>/dev/null | jq -r '.attestation_document // "error"')
if [ "$ATTEST_RESPONSE" != "error" ] && [ -n "$ATTEST_RESPONSE" ]; then
    echo "  ✓ Attestation endpoint returned document"
else
    echo "  ✗ Attestation endpoint failed"
    VALIDATION_PASSED=false
fi

# Final result
echo ""
echo "=========================================="
if [ "$VALIDATION_PASSED" = true ]; then
    echo "VALIDATION PASSED - Deployment successful!"
    echo "=========================================="
    exit 0
else
    echo "VALIDATION FAILED - Deployment has issues"
    echo "=========================================="
    echo ""
    echo "Debug information:"
    echo ""
    echo "--- Enclave Info ---"
    nitro-cli describe-enclaves
    echo ""
    echo "--- Service Logs ---"
    journalctl -u enclave-inbound-proxy.service --no-pager -n 20 || true
    echo ""
    journalctl -u enclave-launcher.service --no-pager -n 20 || true
    exit 1
fi