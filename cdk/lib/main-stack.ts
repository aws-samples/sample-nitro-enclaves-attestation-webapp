import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { Networking } from './constructs/networking';
import { Storage } from './constructs/storage';
import { Auth } from './constructs/auth';
import { Compute } from './constructs/compute';
import { CodeBuildProject } from './constructs/codebuild';
import { CodeDeployApplication } from './constructs/codedeploy';
import { DeploymentPipeline } from './constructs/pipeline';
import { Frontend } from './constructs/frontend';

/**
 * Main Nitro Attestation Stack
 * 
 * Deploys the COMPLETE application with automated CI/CD:
 * 
 * Backend:
 * 1. VPC with private subnets and API Gateway
 * 2. EC2 with Nitro Enclaves enabled (dependencies pre-installed)
 * 3. S3 bucket for source code and artifacts
 * 4. Cognito for authentication
 * 5. CodeBuild for building enclave EIF
 * 6. CodeDeploy for deploying to EC2
 * 7. CodePipeline to orchestrate build → deploy
 * 
 * Frontend:
 * 8. Amplify Hosting for React app
 * 
 * After deployment:
 * 1. Upload source code: ./scripts/package-and-upload.sh
 * 2. Pipeline automatically builds EIF and deploys to EC2
 * 3. Enclave and services start automatically via systemd
 * 4. Connect Git repo to Amplify for frontend deployments
 */
export class NitroAttestationStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // ==================== Storage ====================
    const storage = new Storage(this, 'Storage', {
      accountId: this.account,
      region: this.region,
    });

    // ==================== Authentication ====================
    const auth = new Auth(this, 'Auth', {
      accountId: this.account,
      region: this.region,
    });

    // ==================== Networking ====================
    const networking = new Networking(this, 'Networking', {
      userPoolId: auth.userPool.userPoolId,
      userPoolClientId: auth.userPoolClient.userPoolClientId,
    });

    // ==================== CodeBuild ====================
    const codebuild = new CodeBuildProject(this, 'CodeBuild', {
      eifBucket: storage.eifBucket,
    });

    // ==================== Compute ====================
    const compute = new Compute(this, 'Compute', {
      vpc: networking.vpc,
      securityGroup: networking.ec2SecurityGroup,
      eifBucket: storage.eifBucket,
      eifBucketParam: storage.eifBucketParam,
      eifKeyParam: storage.eifKeyParam,
      metadataKeyParam: storage.metadataKeyParam,
      nlbListener: networking.nlbListener,
    });

    // ==================== CodeDeploy ====================
    const codedeploy = new CodeDeployApplication(this, 'CodeDeploy', {
      asg: compute.asg,
      ec2Role: compute.ec2Role,
    });

    // ==================== CodePipeline ====================
    const pipelineConstruct = new DeploymentPipeline(this, 'Pipeline', {
      sourceBucket: storage.eifBucket,
      buildProject: codebuild.buildProject,
      deploymentGroup: codedeploy.deploymentGroup,
    });


    // ==================== Frontend (Amplify) ====================
    const frontend = new Frontend(this, 'Frontend', {
      apiEndpoint: networking.getApiEndpoint(this.region),
      userPool: auth.userPool,
      userPoolClient: auth.userPoolClient,
    });

    // ==================== Outputs ====================
    new cdk.CfnOutput(this, 'VpcId', {
      value: networking.vpc.vpcId,
      description: 'VPC ID',
    });

    new cdk.CfnOutput(this, 'EifBucketName', {
      value: storage.eifBucket.bucketName,
      description: 'S3 bucket for source code and EIF storage',
    });

    new cdk.CfnOutput(this, 'CodeBuildProject', {
      value: codebuild.buildProject.projectName,
      description: 'CodeBuild project for building enclave',
    });

    new cdk.CfnOutput(this, 'CodeDeployApplication', {
      value: codedeploy.application.applicationName,
      description: 'CodeDeploy application name',
    });

    new cdk.CfnOutput(this, 'PipelineName', {
      value: pipelineConstruct.pipeline.pipelineName,
      description: 'CodePipeline name',
    });

    new cdk.CfnOutput(this, 'AsgName', {
      value: compute.asg.autoScalingGroupName,
      description: 'Auto Scaling Group Name',
    });

    new cdk.CfnOutput(this, 'ApiEndpoint', {
      value: networking.getApiEndpoint(this.region),
      description: 'API Gateway endpoint URL',
    });

    new cdk.CfnOutput(this, 'UserPoolId', {
      value: auth.userPool.userPoolId,
      description: 'Cognito User Pool ID',
    });

    new cdk.CfnOutput(this, 'UserPoolClientId', {
      value: auth.userPoolClient.userPoolClientId,
      description: 'Cognito User Pool Client ID',
    });

    new cdk.CfnOutput(this, 'CognitoDomain', {
      value: auth.getCognitoDomainUrl(this.region),
      description: 'Cognito Hosted UI Domain',
    });

    new cdk.CfnOutput(this, 'AmplifyAppId', {
      value: frontend.amplifyApp.attrAppId,
      description: 'Amplify Application ID',
    });

    new cdk.CfnOutput(this, 'AmplifyAppUrl', {
      value: frontend.appUrl,
      description: 'Amplify App URL (connect Git repo to enable)',
    });

    new cdk.CfnOutput(this, 'DeploymentInstructions', {
      value: `Upload source: ./scripts/package-and-upload.sh ${storage.eifBucket.bucketName}`,
      description: 'How to trigger a backend deployment',
    });
  }
}
