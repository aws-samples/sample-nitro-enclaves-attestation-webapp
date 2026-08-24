#!/bin/bash
# Deploy frontend to Amplify
# Usage: ./scripts/deploy-frontend.sh [stack-name] [aws-profile]
#
# Examples:
#   ./scripts/deploy-frontend.sh                                    # default stack, default profile
#   ./scripts/deploy-frontend.sh NitroAttestationStack sudhir-ue2   # explicit stack + profile
#   AWS_PROFILE=sudhir-ue2 ./scripts/deploy-frontend.sh             # profile via env var
#
# Reads Amplify App ID and API endpoint from CDK outputs file (cdk/cdk-outputs.json).
# Run 'npx cdk deploy' first to generate the outputs file.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FRONTEND_DIR="$PROJECT_ROOT/frontend"
CDK_DIR="$PROJECT_ROOT/cdk"
CDK_OUTPUTS_FILE="$CDK_DIR/cdk-outputs.json"

STACK_NAME="${1:-NitroAttestationStack}"
AWS_PROFILE_NAME="${2:-${AWS_PROFILE:-}}"
BRANCH="main"

echo "========================================"
echo "Deploying Frontend to Amplify"
echo "========================================"

# Verify CDK outputs file exists
if [ ! -f "$CDK_OUTPUTS_FILE" ]; then
  echo "ERROR: CDK outputs file not found at: $CDK_OUTPUTS_FILE"
  echo ""
  echo "Run 'cd cdk && npx cdk deploy $STACK_NAME' first to generate outputs."
  exit 1
fi

# Read values from CDK outputs
echo "Reading outputs from: $CDK_OUTPUTS_FILE (stack: $STACK_NAME)"

APP_ID=$(jq -r ".[\"$STACK_NAME\"].AmplifyAppId // empty" "$CDK_OUTPUTS_FILE")
API_ENDPOINT=$(jq -r ".[\"$STACK_NAME\"].ApiEndpoint // empty" "$CDK_OUTPUTS_FILE")
USER_POOL_ID=$(jq -r ".[\"$STACK_NAME\"].UserPoolId // empty" "$CDK_OUTPUTS_FILE")
USER_POOL_CLIENT_ID=$(jq -r ".[\"$STACK_NAME\"].UserPoolClientId // empty" "$CDK_OUTPUTS_FILE")

# Extract region from API endpoint URL (e.g., https://xxx.execute-api.us-east-2.amazonaws.com)
AWS_DEPLOY_REGION=$(echo "$API_ENDPOINT" | sed -n 's|.*execute-api\.\([^.]*\)\.amazonaws\.com.*|\1|p')
if [ -z "$AWS_DEPLOY_REGION" ]; then
  # Fallback: extract region from UserPoolId (e.g., us-east-2_XhQttxldl)
  AWS_DEPLOY_REGION=$(echo "$USER_POOL_ID" | cut -d'_' -f1)
fi
if [ -z "$AWS_DEPLOY_REGION" ]; then
  echo "WARNING: Could not determine region from CDK outputs. Using AWS CLI default."
fi

# Validate required values
if [ -z "$APP_ID" ]; then
  echo "ERROR: Could not find AmplifyAppId in CDK outputs for stack '$STACK_NAME'"
  echo ""
  echo "Available stacks in outputs file:"
  jq -r 'keys[]' "$CDK_OUTPUTS_FILE"
  exit 1
fi

if [ -z "$API_ENDPOINT" ]; then
  echo "ERROR: Could not find ApiEndpoint in CDK outputs for stack '$STACK_NAME'"
  exit 1
fi

# Allow environment variable overrides
API_ENDPOINT="${VITE_API_ENDPOINT:-$API_ENDPOINT}"

# Build AWS CLI flags (array so each flag stays a separate, safely-quoted argument)
AWS_FLAGS=()
if [ -n "$AWS_DEPLOY_REGION" ]; then
  AWS_FLAGS+=(--region "$AWS_DEPLOY_REGION")
fi
if [ -n "$AWS_PROFILE_NAME" ]; then
  AWS_FLAGS+=(--profile "$AWS_PROFILE_NAME")
fi

echo "  Region:               ${AWS_DEPLOY_REGION:-<default>}"
echo "  Profile:              ${AWS_PROFILE_NAME:-<default>}"
echo "  Amplify App ID:       $APP_ID"
echo "  API Endpoint:         $API_ENDPOINT"
echo "  User Pool ID:         $USER_POOL_ID"
echo "  User Pool Client ID:  $USER_POOL_CLIENT_ID"
echo ""

# Build frontend
echo "Building frontend..."
cd "$FRONTEND_DIR"

VITE_API_ENDPOINT="$API_ENDPOINT" \
VITE_USER_POOL_ID="$USER_POOL_ID" \
VITE_USER_POOL_CLIENT_ID="$USER_POOL_CLIENT_ID" \
npm run build

# Create deployment
echo "Creating Amplify deployment..."
DEPLOYMENT=$(aws amplify create-deployment --app-id "$APP_ID" --branch-name "$BRANCH" "${AWS_FLAGS[@]}" --output json)
JOB_ID=$(echo "$DEPLOYMENT" | jq -r '.jobId')
UPLOAD_URL=$(echo "$DEPLOYMENT" | jq -r '.zipUploadUrl')

echo "Job ID: $JOB_ID"

# Zip and upload
echo "Packaging and uploading..."
cd dist
zip -rq /tmp/frontend-deploy.zip .
curl -sS -X PUT -H "Content-Type: application/zip" -T /tmp/frontend-deploy.zip "$UPLOAD_URL"

# Start deployment
echo "Starting deployment..."
aws amplify start-deployment --app-id "$APP_ID" --branch-name "$BRANCH" --job-id "$JOB_ID" "${AWS_FLAGS[@]}"

# Cleanup
rm -f /tmp/frontend-deploy.zip

echo ""
echo "========================================"
echo "Deployment Started!"
echo "========================================"
echo "URL: https://$BRANCH.$APP_ID.amplifyapp.com"
echo "Monitor: aws amplify get-job --app-id $APP_ID --branch-name $BRANCH --job-id $JOB_ID"
