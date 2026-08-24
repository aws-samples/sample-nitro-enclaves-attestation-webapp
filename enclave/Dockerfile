# Dockerfile for the Nitro Enclave attestation application.
#
# Reproducibility:
# - Python dependencies are fully pinned in requirements.txt.
# - The base image is pinned by digest (sha256) below rather than by the
#   mutable ':2023' tag. A digest is immutable, so every CodeBuild run resolves
#   the exact same base layers and the enclave measurement (PCR0) stays stable.
#   To move to a newer base, update the digest deliberately and re-measure.
# - PYTHONDONTWRITEBYTECODE and `pip --no-compile` avoid .pyc files, whose
#   embedded source timestamps would otherwise vary between builds.
# - The build is invoked with BuildKit and a SOURCE_DATE_EPOCH derived from the
#   S3 source object's timestamp (see the CodeBuild spec) so layer and file
#   timestamps are normalized. Rebuilding the same source revision then yields a
#   byte-identical EIF and the same PCR0.
# The digest is referenced directly on FROM (not via an ARG) so static analysis
# can confirm the base is pinned to an explicit, non-latest version.
FROM public.ecr.aws/amazonlinux/amazonlinux:2023@sha256:5d271dd33b628252c31c15f5449e50d7c4e9f93badf9342f9b1e2a8d326fbe84
#checkov:skip=CKV_DOCKER_2:HEALTHCHECK is not applicable; the image is converted to an EIF and run as a Nitro Enclave, not as a long-running container
#checkov:skip=CKV_DOCKER_3:Running as a non-root in-image user is not the isolation boundary for a Nitro Enclave; the enclave VM boundary is

# Declared so BuildKit accepts the build arg; BuildKit uses SOURCE_DATE_EPOCH to
# normalize timestamps regardless of whether the Dockerfile references it.
ARG SOURCE_DATE_EPOCH

# Install system dependencies (kept lean to minimize the EIF).
# - iproute is required at runtime: start.sh brings up loopback with `ip`.
# - ca-certificates is kept for the Python ssl/hashlib trust store.
# - Weak (recommended) dependencies and package docs are excluded, and the dnf
#   cache is removed, to keep the enclave image and its EIF small.
# Deliberately NOT installed: the openssl CLI (the cryptography wheel bundles its
# own OpenSSL and python3 pulls openssl-libs for `ssl`/`hashlib`), and the
# build/host archive tools (findutils, tar, gzip) which the enclave does not use
# at runtime (all Python dependencies are pinned manylinux wheels).
RUN dnf install -y --setopt=install_weak_deps=False --setopt=tsflags=nodocs \
    python3 \
    python3-pip \
    ca-certificates \
    iproute \
    && dnf clean all \
    && rm -rf /var/cache/dnf /var/log/dnf* /tmp/*

# Create app directory
WORKDIR /app

# Do not write .pyc files (their embedded timestamps break reproducibility)
ENV PYTHONDONTWRITEBYTECODE=1

# Copy requirements and install Python dependencies (pinned, no bytecode)
COPY requirements.txt /app/
RUN python3 -m pip install --no-cache-dir --no-compile -r requirements.txt

# Copy shared NSM components
COPY shared/ /app/shared/

# Copy application code
COPY . /app/

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app:/app/shared:$PYTHONPATH

# Copy startup script
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Run the startup script
CMD ["/app/start.sh"]