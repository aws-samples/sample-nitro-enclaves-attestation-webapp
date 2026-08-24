#!/bin/bash
# Package source code and upload to S3 to trigger CodePipeline
# Usage: ./scripts/package-and-upload.sh [bucket-name]
#
# This script packages all source code needed for:
# - CodeBuild: Building the enclave EIF
# - CodeDeploy: Deploying to EC2 (appspec.yml, deploy scripts, systemd services)

set -e

# Get bucket name from argument, cdk-outputs.json, SSM parameter, or CloudFormation
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CDK_OUTPUTS="$PROJECT_ROOT/cdk/cdk-outputs.json"
STACK_NAME="${STACK_NAME:-NitroAttestationStack}"

if [ -n "$1" ]; then
    BUCKET_NAME="$1"
else
    # Try 1: Read from cdk-outputs.json (fastest, works locally)
    if [ -f "$CDK_OUTPUTS" ]; then
        echo "Reading bucket name from cdk/cdk-outputs.json..."
        BUCKET_NAME=$(grep -o '"EifBucketName": *"[^"]*"' "$CDK_OUTPUTS" | head -1 | sed 's/.*": *"//;s/"//')
    fi

    # Try 2: SSM parameter (works on EC2 or with correct AWS config)
    if [ -z "$BUCKET_NAME" ]; then
        echo "Fetching bucket name from SSM..."
        BUCKET_NAME=$(aws ssm get-parameter --name /nitro-attestation/eif-bucket --query Parameter.Value --output text 2>/dev/null || echo "")
    fi

    # Try 3: CloudFormation stack outputs
    if [ -z "$BUCKET_NAME" ]; then
        echo "Fetching bucket name from CloudFormation stack outputs..."
        BUCKET_NAME=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
            --query "Stacks[0].Outputs[?OutputKey=='EifBucketName'].OutputValue" --output text 2>/dev/null || echo "")
    fi
fi

if [ -z "$BUCKET_NAME" ]; then
    echo "ERROR: Could not determine bucket name."
    echo ""
    echo "Tried (in order):"
    echo "  1. Command-line argument"
    echo "  2. cdk/cdk-outputs.json (file $([ -f "$CDK_OUTPUTS" ] && echo "exists" || echo "not found"))"
    echo "  3. SSM parameter /nitro-attestation/eif-bucket"
    echo "  4. CloudFormation stack '$STACK_NAME' outputs"
    echo ""
    echo "Usage: $0 [bucket-name]"
    echo "Or deploy CDK first: cd cdk && npx cdk deploy $STACK_NAME --outputs-file cdk-outputs.json"
    exit 1
fi

echo "========================================"
echo "Packaging Nitro Enclaves Source Code"
echo "========================================"
echo "Target bucket: $BUCKET_NAME"

# Create temp directory
TEMP_DIR=$(mktemp -d)
ZIP_FILE="$TEMP_DIR/source.zip"

echo "Creating source package..."

# Package enclave directory (required for building EIF)
zip -r "$ZIP_FILE" enclave/ \
    -x "*.pyc" \
    -x "*__pycache__*" \
    -x "*.eif"

# Add proxies directory
zip -ur "$ZIP_FILE" proxies/ \
    -x "*.pyc" \
    -x "*__pycache__*"

# Add systemd services (for CodeDeploy)
zip -ur "$ZIP_FILE" systemd/

# Add deploy scripts and appspec (for CodeDeploy)
zip -ur "$ZIP_FILE" deploy/

echo ""
echo "Package contents:"
unzip -l "$ZIP_FILE" | head -50
echo "... ($(unzip -l "$ZIP_FILE" | wc -l) total entries)"

echo ""
echo "Uploading to S3..."
aws s3 cp "$ZIP_FILE" "s3://$BUCKET_NAME/source/source.zip"

# Cleanup
rm -rf "$TEMP_DIR"

echo ""
echo "========================================"
echo "Upload Complete!"
echo "========================================"
echo "Source uploaded to: s3://$BUCKET_NAME/source/source.zip"
echo ""
echo "CodePipeline will be triggered automatically."
echo "Monitor progress:"
echo "  - CodePipeline Console: https://console.aws.amazon.com/codesuite/codepipeline/pipelines/nitro-attestation-pipeline"
echo "  - CodeBuild: aws codebuild list-builds-for-project --project-name nitro-attestation-enclave-builder"
echo ""