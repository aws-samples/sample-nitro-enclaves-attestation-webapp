# Scripts Documentation

This directory contains the two helper scripts needed to deploy the solution.
Everything else is automated by CDK and CodePipeline. On-instance operations and
troubleshooting are done over AWS Systems Manager (SSM) Session Manager — see the
"Debugging on the instance" section of the [documentation](../docs/index.html).

## Quick Reference

| Script | Purpose | When to Use |
|--------|---------|-------------|
| `package-and-upload.sh` | Package source + upload to S3 | Trigger CodePipeline (build + deploy) |
| `deploy-frontend.sh` | Build + deploy frontend to Amplify | After frontend changes |

---

### `package-and-upload.sh`
**Purpose:** Package the source and upload to S3 to trigger CodePipeline.

```bash
# Auto-detect bucket from SSM
./scripts/package-and-upload.sh

# Explicit bucket name
./scripts/package-and-upload.sh my-bucket-name
```

**What it does:**
1. Creates a zip with `enclave/`, `proxies/`, `systemd/`, and `deploy/`
2. Uploads to `s3://<bucket>/source/source.zip`
3. EventBridge triggers CodePipeline, which runs CodeBuild (build the EIF) and
   CodeDeploy (deploy to the EC2 Auto Scaling group)

---

### `deploy-frontend.sh`
**Purpose:** Build the React frontend and deploy to AWS Amplify.

```bash
# Usage: deploy-frontend.sh <CDK_STACK_NAME> <AWS_PROFILE>
./scripts/deploy-frontend.sh NitroAttestationStack my-profile
```

**What it does:**
1. Reads CDK outputs (Amplify App ID, API endpoint, Cognito config)
2. Builds the frontend with Vite (injects API/auth config as env vars)
3. Creates an Amplify deployment, uploads the built assets, and starts the job

**Required:** CDK stack must already be deployed (needs `cdk/cdk-outputs.json`).

---

## Deploy workflow

```bash
# 1. Deploy infrastructure
cd cdk && npx cdk deploy NitroAttestationBackend --outputs-file cdk-outputs.json

# 2. Package + build the enclave (triggers CodePipeline: build + deploy)
./scripts/package-and-upload.sh

# 3. Deploy the frontend to Amplify
./scripts/deploy-frontend.sh NitroAttestationStack my-profile
```

For verifying a deployment and troubleshooting the enclave, proxy, and services
on the instance, see "Debugging on the instance" in the
[documentation](../docs/index.html) (all steps use SSM Session Manager).
