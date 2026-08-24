#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { BackendStack } from '../lib/backend-stack';
import { FrontendStack } from '../lib/frontend-stack';
import { NitroAttestationStack } from '../lib/main-stack';

/**
 * Nitro Enclaves Attestation CDK App
 * 
 * ============================================================================
 * DEPLOYMENT OPTIONS
 * ============================================================================
 * 
 * 1. Deploy everything (combined stack):
 *    npx cdk deploy NitroAttestationStack
 * 
 * 2. Deploy backend only:
 *    npx cdk deploy NitroAttestationBackend
 * 
 * 3. Deploy frontend with full backend:
 *    npx cdk deploy NitroAttestationBackend NitroAttestationFrontend
 * 
 * 4. Deploy frontend pointing to EXISTING EC2 instance (testing mode):
 *    npx cdk deploy NitroAttestationFrontendDev \
 *      -c vpcId=vpc-xxxxx \
 *      -c backendIp=10.0.1.100 \
 *      -c subnetIds=subnet-aaa,subnet-bbb
 * 
 * 5. Get existing instance info for frontend dev deployment:
 *    # Get VPC ID
 *    aws ec2 describe-instances --instance-ids <instance-id> \
 *      --query 'Reservations[0].Instances[0].VpcId' --output text
 *    
 *    # Get Private IP
 *    aws ec2 describe-instances --instance-ids <instance-id> \
 *      --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text
 *    
 *    # Get Subnet IDs (need at least 2 for NLB)
 *    aws ec2 describe-subnets --filters "Name=vpc-id,Values=<vpc-id>" \
 *      --query 'Subnets[*].SubnetId' --output text
 * 
 * ============================================================================
 */

const app = new cdk.App();

// cdk-nag v3: Use Validations API for policy checks and acknowledgements
cdk.Validations.of(app).addPlugins(
  new AwsSolutionsChecks(app, { verbose: true })
);

// Get environment configuration
const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION || 'us-east-1',
};

// ============================================================================
// Context parameters for existing EC2 mode
// ============================================================================
const existingVpcId = app.node.tryGetContext('vpcId');
const backendPrivateIp = app.node.tryGetContext('backendIp');
const subnetIdsStr = app.node.tryGetContext('subnetIds');
const subnetIds = subnetIdsStr ? subnetIdsStr.split(',') : undefined;
const backendPort = parseInt(app.node.tryGetContext('backendPort') || '8000');

// ============================================================================
// Option 1: Combined Stack (all-in-one)
// ============================================================================
const mainStack = new NitroAttestationStack(app, 'NitroAttestationStack', {
  env,
  description: 'Nitro Enclaves Attestation Demo - Combined Stack',
});


// ============================================================================
// Option 2: Separate Backend + Frontend Stacks
// ============================================================================

// Backend Stack (VPC, EC2, Cognito, S3, CodeBuild, NLB, API Gateway)
const backendStack = new BackendStack(app, 'NitroAttestationBackend', {
  env,
  description: 'Nitro Enclaves Attestation Demo - Backend Infrastructure',
});

// Frontend Stack - depends on backend
new FrontendStack(app, 'NitroAttestationFrontend', {
  env,
  description: 'Nitro Enclaves Attestation Demo - Frontend (Amplify)',
  apiEndpoint: backendStack.apiEndpoint,
  userPoolId: backendStack.userPoolId,
  userPoolClientId: backendStack.userPoolClientId,
});

// ============================================================================
// Option 3: Frontend Only - Pointing to Existing EC2 (Dev/Testing)
// ============================================================================
// 
// This creates:
// - API Gateway (HTTP API)
// - VPC Link
// - NLB pointing to your existing EC2 instance
// - Amplify hosting
//
// Use when you have an existing EC2 running the backend and want to
// deploy just the frontend infrastructure for testing.

if (existingVpcId && backendPrivateIp && subnetIds) {
  new FrontendStack(app, 'NitroAttestationFrontendDev', {
    env,
    description: 'Nitro Enclaves Attestation Demo - Frontend Dev (existing EC2)',
    existingVpcId,
    backendPrivateIp,
    subnetIds,
    backendPort,
  });
}

// ============================================================================
// Tags
// ============================================================================
cdk.Tags.of(app).add('Project', 'NitroAttestationDemo');
cdk.Tags.of(app).add('ManagedBy', 'CDK');
