import * as cdk from 'aws-cdk-lib';
import * as amplify from 'aws-cdk-lib/aws-amplify';
import * as codebuild from 'aws-cdk-lib/aws-codebuild';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import { Construct } from 'constructs';

export interface FrontendProps {
  /**
   * The API endpoint URL (API Gateway)
   */
  readonly apiEndpoint?: string;
  
  /**
   * Cognito User Pool
   */
  readonly userPool?: cognito.IUserPool;
  
  /**
   * Cognito User Pool Client
   */
  readonly userPoolClient?: cognito.IUserPoolClient;
  
  /**
   * GitHub repository (owner/repo format)
   */
  readonly githubRepo?: string;
  
  /**
   * GitHub branch to deploy
   */
  readonly branch?: string;
  
  /**
   * GitHub OAuth token (stored in Secrets Manager)
   * Required for private repos
   */
  readonly githubTokenSecretArn?: string;
}

export class Frontend extends Construct {
  public readonly amplifyApp: amplify.CfnApp;
  public readonly amplifyBranch: amplify.CfnBranch;
  public readonly appUrl: string;

  constructor(scope: Construct, id: string, props: FrontendProps = {}) {
    super(scope, id);

    const branch = props.branch || 'main';

    // ==================== Amplify Service Role ====================
    const amplifyRole = new iam.Role(this, 'AmplifyRole', {
      assumedBy: new iam.ServicePrincipal('amplify.amazonaws.com'),
      description: 'Role for Amplify to access resources',
    });

    // ==================== Amplify App ====================
    this.amplifyApp = new amplify.CfnApp(this, 'AmplifyApp', {
      name: 'nitro-attestation-frontend',
      description: 'Nitro Enclaves Attestation Demo Frontend',
      iamServiceRole: amplifyRole.roleArn,
      
      // Build settings for Vite React app
      buildSpec: cdk.Fn.sub(`
version: 1
frontend:
  phases:
    preBuild:
      commands:
        - cd frontend
        - npm ci
    build:
      commands:
        - npm run build
  artifacts:
    baseDirectory: frontend/dist
    files:
      - '**/*'
  cache:
    paths:
      - frontend/node_modules/**/*
`),
      
      // Environment variables
      environmentVariables: [
        {
          name: 'VITE_API_ENDPOINT',
          value: props.apiEndpoint || '',
        },
        {
          name: 'VITE_USER_POOL_ID',
          value: props.userPool?.userPoolId || '',
        },
        {
          name: 'VITE_USER_POOL_CLIENT_ID',
          value: props.userPoolClient?.userPoolClientId || '',
        },
        {
          name: '_LIVE_UPDATES',
          value: JSON.stringify([
            { pkg: '@aws-amplify/cli', type: 'npm', version: 'latest' },
          ]),
        },
      ],
      
      // Custom rules for SPA routing
      customRules: [
        {
          source: '</^[^.]+$|\\.(?!(css|gif|ico|jpg|js|png|txt|svg|woff|woff2|ttf|map|json)$)([^.]+$)/>',
          target: '/index.html',
          status: '200',
        },
      ],
      
      // Platform
      platform: 'WEB',
    });

    // ==================== Branch ====================
    this.amplifyBranch = new amplify.CfnBranch(this, 'MainBranch', {
      appId: this.amplifyApp.attrAppId,
      branchName: branch,
      enableAutoBuild: true,
      enablePullRequestPreview: false,
      stage: 'PRODUCTION',
      environmentVariables: [
        {
          name: 'AMPLIFY_MONOREPO_APP_ROOT',
          value: '.',
        },
      ],
    });

    // Set the app URL
    this.appUrl = `https://${branch}.${this.amplifyApp.attrDefaultDomain}`;
  }

  /**
   * Update the Cognito callback URLs with the Amplify app URL
   */
  public updateCognitoCallbackUrls(userPoolClient: cognito.UserPoolClient): void {
    // Note: This would require updating the user pool client after deployment
    // Since we don't know the Amplify URL until after deployment
    // This is typically done manually or via a custom resource
  }
}