import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { Frontend } from './constructs/frontend';
import { ApiGateway } from './constructs/api';
import { Auth } from './constructs/auth';

export interface FrontendStackProps extends cdk.StackProps {
  /**
   * Mode 1: Direct API endpoint (for full backend stack)
   * API Gateway endpoint URL from backend stack
   */
  readonly apiEndpoint?: string;
  
  /**
   * Mode 2: Connect to existing EC2 instance
   * Existing VPC ID where the EC2 instance is running
   */
  readonly existingVpcId?: string;
  
  /**
   * Private IP of the existing EC2 instance (required with existingVpcId)
   */
  readonly backendPrivateIp?: string;
  
  /**
   * Subnet IDs in the VPC (required with existingVpcId)
   */
  readonly subnetIds?: string[];
  
  /**
   * Backend port (default: 8000)
   */
  readonly backendPort?: number;
  
  /**
   * Cognito User Pool ID from backend stack (optional - if not provided, creates new)
   */
  readonly userPoolId?: string;
  
  /**
   * Cognito User Pool Client ID from backend stack (optional)
   */
  readonly userPoolClientId?: string;
  
  /**
   * GitHub branch to deploy (default: main)
   */
  readonly branch?: string;
  
  /**
   * Skip Cognito creation (use mock auth)
   */
  readonly skipAuth?: boolean;
}

/**
 * Frontend Stack - Amplify Hosting for the React application
 * 
 * Two modes of operation:
 * 
 * 1. Full Backend Mode: Uses apiEndpoint from BackendStack
 *    - For production deployments with full CDK backend
 * 
 * 2. Existing EC2 Mode: Creates API Gateway + NLB + Cognito pointing to existing instance
 *    - For testing with an existing EC2 running the backend
 *    - Requires: existingVpcId, backendPrivateIp, subnetIds
 *    - Creates its own Cognito user pool (self-contained)
 */
export class FrontendStack extends cdk.Stack {
  public readonly frontend: Frontend;
  public readonly api?: ApiGateway;
  public readonly auth?: Auth;
  public readonly appUrl: string;
  public readonly apiEndpoint: string;
  public readonly userPoolId?: string;
  public readonly userPoolClientId?: string;

  constructor(scope: Construct, id: string, props: FrontendStackProps) {
    super(scope, id, props);

    // Determine API endpoint
    if (props.apiEndpoint) {
      // Mode 1: Use provided API endpoint (from backend stack)
      this.apiEndpoint = props.apiEndpoint;
    } else if (props.existingVpcId && props.backendPrivateIp && props.subnetIds) {
      // Mode 2: Create API Gateway + NLB for existing EC2
      this.api = new ApiGateway(this, 'Api', {
        existingVpcId: props.existingVpcId,
        backendPrivateIp: props.backendPrivateIp,
        backendPort: props.backendPort || 8000,
        subnetIds: props.subnetIds,
      });
      this.apiEndpoint = this.api.apiEndpoint;
    } else {
      throw new Error(
        'Either apiEndpoint OR (existingVpcId + backendPrivateIp + subnetIds) must be provided'
      );
    }

    // ==================== Cognito Authentication ====================
    // Create Cognito if not provided and not skipped
    if (props.userPoolId && props.userPoolClientId) {
      // Use existing Cognito from backend stack
      this.userPoolId = props.userPoolId;
      this.userPoolClientId = props.userPoolClientId;
    } else if (!props.skipAuth) {
      // Create new Cognito user pool (self-contained frontend)
      this.auth = new Auth(this, 'Auth', {
        accountId: this.account,
        region: this.region,
      });
      this.userPoolId = this.auth.userPool.userPoolId;
      this.userPoolClientId = this.auth.userPoolClient.userPoolClientId;
    }

    // ==================== Frontend (Amplify) ====================
    this.frontend = new Frontend(this, 'Frontend', {
      apiEndpoint: this.apiEndpoint,
      branch: props.branch || 'main',
      userPool: this.auth?.userPool,
      userPoolClient: this.auth?.userPoolClient,
    });

    this.appUrl = this.frontend.appUrl;

    // Update Cognito callback URLs with Amplify URL
    if (this.auth) {
      // Note: We can't easily update callback URLs after creation
      // The frontend code will use the hosted UI or direct API calls
    }

    // ==================== Outputs ====================
    new cdk.CfnOutput(this, 'AmplifyAppId', {
      value: this.frontend.amplifyApp.attrAppId,
      description: 'Amplify App ID',
      exportName: `${this.stackName}-AmplifyAppId`,
    });

    new cdk.CfnOutput(this, 'AmplifyAppUrl', {
      value: this.appUrl,
      description: 'Amplify App URL',
      exportName: `${this.stackName}-AppUrl`,
    });

    new cdk.CfnOutput(this, 'ApiEndpoint', {
      value: this.apiEndpoint,
      description: 'API Gateway endpoint URL',
      exportName: `${this.stackName}-ApiEndpoint`,
    });

    new cdk.CfnOutput(this, 'AmplifyConsoleUrl', {
      value: `https://${this.region}.console.aws.amazon.com/amplify/home?region=${this.region}#/${this.frontend.amplifyApp.attrAppId}`,
      description: 'Amplify Console URL',
    });

    if (this.api) {
      new cdk.CfnOutput(this, 'NlbArn', {
        value: this.api.nlb?.loadBalancerArn || 'N/A',
        description: 'Network Load Balancer ARN',
      });
    }

    // Cognito outputs
    if (this.userPoolId) {
      new cdk.CfnOutput(this, 'UserPoolId', {
        value: this.userPoolId,
        description: 'Cognito User Pool ID',
        exportName: `${this.stackName}-UserPoolId`,
      });
    }

    if (this.userPoolClientId) {
      new cdk.CfnOutput(this, 'UserPoolClientId', {
        value: this.userPoolClientId,
        description: 'Cognito User Pool Client ID',
        exportName: `${this.stackName}-UserPoolClientId`,
      });
    }

    if (this.auth) {
      new cdk.CfnOutput(this, 'CognitoDomain', {
        value: this.auth.getCognitoDomainUrl(this.region),
        description: 'Cognito Hosted UI Domain',
      });
    }

    // Instructions for connecting to Git
    new cdk.CfnOutput(this, 'NextSteps', {
      value: 'Connect your Git repository in the Amplify Console to enable automatic deployments',
      description: 'Next steps after deployment',
    });
  }
}