import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';

export interface StorageProps {
  readonly accountId: string;
  readonly region: string;
}

export class Storage extends Construct {
  public readonly eifBucket: s3.Bucket;
  public readonly eifBucketParam: ssm.StringParameter;
  public readonly eifKeyParam: ssm.StringParameter;
  public readonly metadataKeyParam: ssm.StringParameter;

  constructor(scope: Construct, id: string, props: StorageProps) {
    super(scope, id);

    // ==================== S3 Bucket for EIF ====================
    this.eifBucket = new s3.Bucket(this, 'EifBucket', {
      bucketName: `nitro-attestation-eif-${props.accountId}-${props.region}`,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      versioned: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      // Ensure bucket is private - block all public access
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      publicReadAccess: false,
      // Enforce SSL for all requests
      enforceSSL: true,
      // Enable EventBridge notifications so S3 events trigger CodePipeline
      eventBridgeEnabled: true,
    });

    // ==================== SSM Parameters ====================
    this.eifBucketParam = new ssm.StringParameter(this, 'EifBucketParam', {
      parameterName: '/nitro-attestation/eif-bucket',
      stringValue: this.eifBucket.bucketName,
      description: 'S3 bucket name for EIF storage',
    });

    this.eifKeyParam = new ssm.StringParameter(this, 'EifKeyParam', {
      parameterName: '/nitro-attestation/eif-key',
      stringValue: 'enclave/attestation-enclave.eif',
      description: 'S3 key for the EIF file',
    });

    this.metadataKeyParam = new ssm.StringParameter(this, 'MetadataKeyParam', {
      parameterName: '/nitro-attestation/metadata-key',
      stringValue: 'enclave/metadata.json',
      description: 'S3 key for enclave metadata',
    });

    // ==================== cdk-nag Acknowledgements ====================
    cdk.Validations.of(this).acknowledge({
      id: 'AwsSolutions-S1',
      reason: 'S3 access logging out of scope for sample app',
    });
    // The S3 EventBridge notification handler Lambda uses an AWS managed policy
    const nagRules: Record<string, string> = {};
    nagRules['AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole]'] =
      'CDK-managed Lambda for S3 EventBridge notifications uses AWS managed policy';
    cdk.Stack.of(this).node.addMetadata('aws:cdk:acknowledged-rules', nagRules);
  }
}
