import * as cdk from 'aws-cdk-lib';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import { Construct } from 'constructs';
import * as fs from 'fs';
import * as path from 'path';

export interface ComputeProps {
  readonly vpc: ec2.Vpc;
  readonly securityGroup: ec2.SecurityGroup;
  readonly eifBucket: s3.Bucket;
  readonly eifBucketParam: ssm.StringParameter;
  readonly eifKeyParam: ssm.StringParameter;
  readonly metadataKeyParam: ssm.StringParameter;
  readonly nlbListener: elbv2.NetworkListener;
}

export class Compute extends Construct {
  public readonly asg: autoscaling.AutoScalingGroup;
  public readonly ec2Role: iam.Role;

  constructor(scope: Construct, id: string, props: ComputeProps) {
    super(scope, id);

    // ==================== IAM Role ====================
    this.ec2Role = new iam.Role(this, 'Ec2Role', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
      ],
    });

    // Grant SSM parameter read permissions (does not produce wildcards)
    props.eifBucketParam.grantRead(this.ec2Role);
    props.eifKeyParam.grantRead(this.ec2Role);
    props.metadataKeyParam.grantRead(this.ec2Role);

    // CodeDeploy agent permissions (required for VPC endpoint with enable_auth_policy)
    this.ec2Role.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'codedeploy-commands-secure:GetDeploymentSpecification',
        'codedeploy-commands-secure:PollHostCommand',
        'codedeploy-commands-secure:PutHostCommandAcknowledgement',
        'codedeploy-commands-secure:PutHostCommandComplete',
      ],
      resources: ['*'],
    }));

    // CodeDeploy agent permissions - scoped to specific application/group
    const cdRegion = cdk.Stack.of(this).region;
    const cdAccount = cdk.Stack.of(this).account;
    this.ec2Role.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'codedeploy:GetDeploymentConfig',
        'codedeploy:GetApplicationRevision',
        'codedeploy:GetDeployment',
        'codedeploy:ListDeployments',
        'codedeploy:RegisterApplicationRevision',
      ],
      resources: [
        `arn:aws:codedeploy:${cdRegion}:${cdAccount}:application:nitro-attestation-app`,
        `arn:aws:codedeploy:${cdRegion}:${cdAccount}:deploymentgroup:nitro-attestation-app/nitro-attestation-deployment-group`,
        `arn:aws:codedeploy:${cdRegion}:${cdAccount}:deploymentconfig:CodeDeployDefault.AllAtOnce`,
      ],
    }));

    // S3 read for CodeDeploy artifacts - scoped to pipeline artifacts bucket and EIF bucket
    this.ec2Role.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        's3:GetObject',
        's3:GetObjectVersion',
        's3:GetBucketLocation',
        's3:ListBucket',
      ],
      resources: [
        props.eifBucket.bucketArn,
        `${props.eifBucket.bucketArn}/*`,
      ],
    }));

    // KMS decrypt for CodePipeline artifact bucket (encrypted with KMS) - scoped in pipeline construct
    // Note: KMS key ARN not yet known here; use condition to limit to account keys
    this.ec2Role.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'kms:Decrypt',
        'kms:DescribeKey',
      ],
      resources: [
        `arn:aws:kms:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:key/*`,
      ],
    }));

    // ==================== User Data ====================
    const userDataScriptPath = path.join(__dirname, '..', '..', 'scripts', 'ec2-user-data.sh');
    const userDataScript = fs.readFileSync(userDataScriptPath, 'utf-8');

    const userData = ec2.UserData.forLinux();
    userData.addCommands(userDataScript);

    // ==================== Launch Template ====================
    const launchTemplate = new ec2.LaunchTemplate(this, 'LaunchTemplate', {
      // AWS Graviton (ARM64). Nitro Enclaves is supported on Graviton, and because
      // Graviton has no SMT (1 vCPU = 1 physical core) an enclave can be allocated a
      // single vCPU. c8g.large (2 vCPU / 4 GiB) gives 1 vCPU + 2 GiB to the enclave and
      // leaves 1 vCPU + 2 GiB for the parent. Specified as a string so it does not
      // depend on the C8G enum being present in the installed aws-cdk-lib version.
      instanceType: new ec2.InstanceType('c8g.large'),
      machineImage: ec2.MachineImage.latestAmazonLinux2023({
        cpuType: ec2.AmazonLinuxCpuType.ARM_64,
      }),
      role: this.ec2Role,
      securityGroup: props.securityGroup,
      userData,
      blockDevices: [{
        deviceName: '/dev/xvda',
        volume: ec2.BlockDeviceVolume.ebs(30, {
          encrypted: true,
          volumeType: ec2.EbsDeviceVolumeType.GP3,
        }),
      }],
    });

    // Enable Nitro Enclaves on the launch template (not exposed in L2 construct)
    const cfnLaunchTemplate = launchTemplate.node.defaultChild as ec2.CfnLaunchTemplate;
    cfnLaunchTemplate.addPropertyOverride('LaunchTemplateData.EnclaveOptions.Enabled', true);

    // ==================== Auto Scaling Group ====================
    this.asg = new autoscaling.AutoScalingGroup(this, 'Asg', {
      vpc: props.vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      launchTemplate,
      minCapacity: 1,
      maxCapacity: 1,
      desiredCapacity: 1,
      // Health check grace period to allow user data to complete
      healthChecks: autoscaling.HealthChecks.ec2({
        gracePeriod: cdk.Duration.minutes(10),
      }),
      updatePolicy: autoscaling.UpdatePolicy.rollingUpdate({
        maxBatchSize: 1,
        minInstancesInService: 0,
      }),
    });

    // Add tag for identification
    cdk.Tags.of(this.asg).add('Project', 'NitroAttestationDemo');

    // ==================== Attach to NLB ====================
    props.nlbListener.addTargets('AsgTarget', {
      port: 8000,
      targets: [this.asg],
      healthCheck: {
        path: '/health',
        protocol: elbv2.Protocol.HTTP,
      },
    });

    // ==================== cdk-nag Acknowledgements ====================
    cdk.Validations.of(this).acknowledge({
      id: 'AwsSolutions-AS3',
      reason: 'ASG scaling notifications out of scope for sample app',
    });
    cdk.Validations.of(this).acknowledge({
      id: 'Construct-Annotations::@aws-cdk/aws-autoscaling:desiredCapacitySet',
      reason: 'Desired capacity is intentionally set to 1 for single-instance demo; reset on deployment is acceptable',
    });
    // Granular IAM4/IAM5 use '::' which conflicts with Validations.acknowledge() prefix separator.
    // Must write to stack node for cdk-nag to find them.
    const nagRules: Record<string, string> = {};
    nagRules['AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/AmazonSSMManagedInstanceCore]'] =
      'SSM managed policy required for Session Manager access in isolated subnet';
    nagRules['AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AmazonEC2RoleforAWSCodeDeploy]'] =
      'AWS managed policy added by CodeDeploy construct for deployment agent';
    // codedeploy-commands-secure requires Resource::* (AWS API limitation)
    nagRules['AwsSolutions-IAM5[Resource::*]'] =
      'codedeploy-commands-secure APIs require Resource::* (no resource-level scoping)';
    nagRules[`AwsSolutions-IAM5[Resource::arn:aws:kms:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:key/*]`] =
      'KMS key ARN for pipeline artifacts not known at synth time; scoped to account keys';
    // Pipeline grants S3 access to this role for artifact retrieval
    nagRules['AwsSolutions-IAM5[Action::s3:GetBucket*]'] =
      'CDK Pipeline L2 grants wildcard S3 actions to roles it integrates with';
    nagRules['AwsSolutions-IAM5[Action::s3:GetObject*]'] =
      'CDK Pipeline L2 grants wildcard S3 actions to roles it integrates with';
    nagRules['AwsSolutions-IAM5[Action::s3:List*]'] =
      'CDK Pipeline L2 grants wildcard S3 actions to roles it integrates with';
    cdk.Stack.of(this).node.addMetadata('aws:cdk:acknowledged-rules', nagRules);
  }
}
