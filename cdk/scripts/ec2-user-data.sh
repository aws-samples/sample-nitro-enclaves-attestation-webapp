#!/bin/bash
# EC2 User Data Script for Nitro Enclaves Attestation
# 
# This script installs ALL dependencies for the containerized backend architecture:
# - Docker (to run backend container from ECR)
# - AWS CLI (for ECR login)
# - Nitro Enclaves CLI (for enclave management)
# - Python 3 (for vsock proxy only)
# - CodeDeploy agent (for automated deployments)
#
# The backend runs as a Docker container (Python 3.11) pulled from ECR.
# The vsock proxy runs directly on the host (bridges TCP→vsock to enclave).
# Architecture: Client → Backend Container (host network, :8000) → Proxy (:8001) → Enclave (vsock)
#
# v2 - forced instance replacement for containerized architecture

set -e

echo "=========================================="
echo "Nitro Attestation EC2 Bootstrap (v2)"
echo "=========================================="

# Install system dependencies
echo "Installing system dependencies..."
yum update -y
yum install -y \
    aws-nitro-enclaves-cli \
    aws-nitro-enclaves-cli-devel \
    docker \
    python3 \
    python3-pip \
    jq \
    ruby \
    wget \
    awscli

# Verify AWS CLI works
echo "Verifying AWS CLI..."
aws --version

# Start and enable Docker
echo "Starting Docker..."
systemctl enable docker
systemctl start docker

# Install CodeDeploy agent
# Uses 'aws s3 cp' because the instance is in an isolated subnet with no internet.
# The S3 Gateway Endpoint allows S3 API access.
echo "Installing CodeDeploy agent..."
REGION=$(TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") && curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
cd /tmp
aws s3 cp "s3://aws-codedeploy-${REGION}/latest/install" . --region "${REGION}"
chmod +x ./install
./install auto

# Configure agent to use secure endpoint (required for VPC endpoint connectivity)
mkdir -p /etc/codedeploy-agent/conf
cat > /etc/codedeploy-agent/conf/codedeployagent.yml << 'AGENTEOF'
---
:log_aws_wire: false
:log_dir: '/var/log/aws/codedeploy-agent/'
:pid_dir: '/opt/codedeploy-agent/state/.pid/'
:program_name: codedeploy-agent
:root_dir: '/opt/codedeploy-agent/deployment-root'
:verbose: false
:wait_between_runs: 1
:proxy_uri:
:max_revisions: 5
:enable_auth_policy: true
AGENTEOF

systemctl enable codedeploy-agent
systemctl restart codedeploy-agent

# Configure Nitro Enclaves
echo "Configuring Nitro Enclaves..."
usermod -aG ne ec2-user || true

# Set default allocator config (will be overwritten by CodeDeploy from metadata.json).
# 1 vCPU / 2048 MiB reserved for the enclave; c8g.large (Graviton, no SMT) allows a
# single-vCPU enclave and leaves 1 vCPU + ~2 GiB for the parent instance.
mkdir -p /etc/nitro_enclaves
cat > /etc/nitro_enclaves/allocator.yaml << 'EOF'
---
cpu_count: 1
memory_mib: 2048
EOF

# Enable and start allocator
systemctl enable nitro-enclaves-allocator
systemctl start nitro-enclaves-allocator

# Create application directory
echo "Creating application directory..."
mkdir -p /opt/nitro-attestation/{proxies,enclave/shared,logs}
chown -R root:root /opt/nitro-attestation

echo "=========================================="
echo "EC2 Bootstrap Complete! (v2)"
echo "=========================================="
echo ""
echo "Architecture:"
echo "  - Backend: Docker container (Python 3.11) from ECR, --network host"
echo "  - Proxy: Python3 on host, localhost:8001 → vsock to enclave"
echo "  - Enclave: Nitro Enclave with attestation service"
echo ""
echo "The EC2 instance is ready for CodeDeploy deployments."
echo ""
