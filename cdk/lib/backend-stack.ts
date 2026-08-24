import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { Networking } from './constructs/networking';
import { Storage } from './constructs/storage';
import { Auth } from './constructs/auth';
import { Compute } from './constructs/compute';
import { CodeBuildProject } from './constructs/codebuild';

/**
 * Backend Stack - Contains all backend infrastructure
 * - VPC with private subnets and VPC endpoints
 * - S3 bucket for EIF storage
 * - Cognito for authentication
 * - EC2 instance with Nitro Enclaves
 * - CodeBuild for building enclave images
 * - API Gateway with VPC Link to NLB
 */
export class BackendStack extends cdk.Stack {
  public readonly networking: Networking;
  public readonly storage: Storage;
  public readonly auth: Auth;
  public readonly compute: Compute;
  public readonly codebuild: CodeBuildProject;
  
  // Exports for frontend stack
  public readonly apiEndpoint: string;
  public readonly userPoolId: string;
  public readonly userPoolClientId: string;
  public readonly cognitoDomain: string;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // ==================== Networking ====================
    this.networking = new Networking(this, 'Networking');

    // ==================== Storage ====================
    this.storage = new Storage(this, 'Storage', {
      accountId: this.account,
      region: this.region,
    });

    // ==================== Authentication ====================
    this.auth = new Auth(this, 'Auth', {
      accountId: this.account,
      region: this.region,
    });

    // ==================== CodeBuild ====================
    this.codebuild = new CodeBuildProject(this, 'CodeBuild', {
      eifBucket: this.storage.eifBucket,
    });

    // ==================== Compute ====================
    this.compute = new Compute(this, 'Compute', {
      vpc: this.networking.vpc,
      securityGroup: this.networking.ec2SecurityGroup,
      eifBucket: this.storage.eifBucket,
      eifBucketParam: this.storage.eifBucketParam,
      eifKeyParam: this.storage.eifKeyParam,
      metadataKeyParam: this.storage.metadataKeyParam,
      nlbListener: this.networking.nlbListener,
    });

    // Set exported values
    this.apiEndpoint = this.networking.getApiEndpoint(this.region);
    this.userPoolId = this.auth.userPool.userPoolId;
    this.userPoolClientId = this.auth.userPoolClient.userPoolClientId;
    this.cognitoDomain = this.auth.getCognitoDomainUrl(this.region);

    // ==================== Outputs ====================
    new cdk.CfnOutput(this, 'VpcId', {
      value: this.networking.vpc.vpcId,
      description: 'VPC ID',
      exportName: 'NitroAttestation-VpcId',
    });

    new cdk.CfnOutput(this, 'EifBucketName', {
      value: this.storage.eifBucket.bucketName,
      description: 'S3 bucket for EIF storage',
      exportName: 'NitroAttestation-EifBucket',
    });

    new cdk.CfnOutput(this, 'CodeBuildProject', {
      value: this.codebuild.buildProject.projectName,
      description: 'CodeBuild project for building enclave',
      exportName: 'NitroAttestation-CodeBuildProject',
    });

    new cdk.CfnOutput(this, 'AsgName', {
      value: this.compute.asg.autoScalingGroupName,
      description: 'Auto Scaling Group Name',
      exportName: 'NitroAttestation-AsgName',
    });

    new cdk.CfnOutput(this, 'ApiEndpoint', {
      value: this.apiEndpoint,
      description: 'API Gateway endpoint URL',
      exportName: 'NitroAttestation-ApiEndpoint',
    });

    new cdk.CfnOutput(this, 'UserPoolId', {
      value: this.userPoolId,
      description: 'Cognito User Pool ID',
      exportName: 'NitroAttestation-UserPoolId',
    });

    new cdk.CfnOutput(this, 'UserPoolClientId', {
      value: this.userPoolClientId,
      description: 'Cognito User Pool Client ID',
      exportName: 'NitroAttestation-UserPoolClientId',
    });

    new cdk.CfnOutput(this, 'CognitoDomain', {
      value: this.cognitoDomain,
      description: 'Cognito Hosted UI Domain',
      exportName: 'NitroAttestation-CognitoDomain',
    });
  }
}