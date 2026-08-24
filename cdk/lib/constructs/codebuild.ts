import * as cdk from 'aws-cdk-lib';
import * as codebuild from 'aws-cdk-lib/aws-codebuild';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';

export interface CodeBuildProps {
  readonly eifBucket: s3.Bucket;
}

export class CodeBuildProject extends Construct {
  public readonly buildProject: codebuild.Project;
  public readonly buildRole: iam.Role;

  constructor(scope: Construct, id: string, props: CodeBuildProps) {
    super(scope, id);

    // ==================== CodeBuild Role ====================
    this.buildRole = new iam.Role(this, 'CodeBuildRole', {
      assumedBy: new iam.ServicePrincipal('codebuild.amazonaws.com'),
    });

    // Scoped S3 permissions for EIF bucket (specific actions, no wildcards)
    this.buildRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        's3:GetObject',
        's3:GetObjectVersion',
        's3:GetBucketLocation',
        's3:ListBucket',
        's3:PutObject',
        's3:DeleteObject',
      ],
      resources: [
        props.eifBucket.bucketArn,
        `${props.eifBucket.bucketArn}/*`,
      ],
    }));

    // ==================== CodeBuild Project ====================
    // This project builds the enclave EIF and creates a CodeDeploy artifact
    this.buildProject = new codebuild.Project(this, 'EnclaveBuilder', {
      projectName: 'nitro-attestation-enclave-builder',
      description: 'Build Nitro Enclave EIF and deployment artifact',
      environment: {
        buildImage: codebuild.LinuxArmBuildImage.AMAZON_LINUX_2_STANDARD_3_0,
        computeType: codebuild.ComputeType.LARGE,
        privileged: true, // Required for Docker
        environmentVariables: {
          AWS_ACCOUNT_ID: { value: cdk.Stack.of(this).account },
          // Used to derive SOURCE_DATE_EPOCH from the source object's timestamp.
          EIF_BUCKET_NAME: { value: props.eifBucket.bucketName },
        },
      },
      role: this.buildRole,
      // Source is provided by CodePipeline
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          install: {
            'runtime-versions': {
              docker: 23,
            },
            commands: [
              'echo "Installing Nitro CLI..."',
              'amazon-linux-extras install aws-nitro-enclaves-cli -y || yum install aws-nitro-enclaves-cli -y',
              'yum install aws-nitro-enclaves-cli-devel jq -y || true',
            ],
          },
          pre_build: {
            commands: [
              'echo "Source files:"',
              'ls -la',
              // Build enclave Docker image reproducibly.
              // BuildKit + SOURCE_DATE_EPOCH normalize layer/file timestamps so
              // the EIF (and its PCR0 measurement) is reproducible. The epoch is
              // derived from the LastModified of the S3 source object that
              // triggered this build, so rebuilding the same source revision
              // yields a byte-identical EIF. Re-uploading the source (a new S3
              // version) is treated as a new revision with a new timestamp. A
              // fixed epoch is used only as a fallback if the lookup fails.
              'echo "Building Docker image for enclave (reproducible)..."',
              'cd enclave',
              'export DOCKER_BUILDKIT=1',
              'SRC_LM=$(aws s3api head-object --bucket "$EIF_BUCKET_NAME" --key source/source.zip --version-id "$CODEBUILD_RESOLVED_SOURCE_VERSION" --query LastModified --output text 2>/dev/null || true)',
              'if [ -z "$SRC_LM" ] || [ "$SRC_LM" = "None" ]; then SRC_LM=$(aws s3api head-object --bucket "$EIF_BUCKET_NAME" --key source/source.zip --query LastModified --output text 2>/dev/null || true); fi',
              'if [ -n "$SRC_LM" ] && [ "$SRC_LM" != "None" ]; then export SOURCE_DATE_EPOCH=$(date -u -d "$SRC_LM" +%s); else export SOURCE_DATE_EPOCH=1704067200; fi',
              'echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH (S3 source LastModified: ${SRC_LM:-fallback})"',
              'docker build --build-arg SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH -t attestation-enclave .',
              'cd $CODEBUILD_SRC_DIR',
            ],
          },
          build: {
            commands: [
              'echo "Building EIF..."',
              'cd enclave',
              'nitro-cli build-enclave --docker-uri attestation-enclave:latest --output-file attestation-enclave.eif > build-output.json',
              'cat build-output.json',
              // Report the enclave image and EIF size for visibility.
              'docker image ls attestation-enclave:latest',
              'ls -lh attestation-enclave.eif',
              // Size the enclave memory from the EIF on disk: EIF bytes x4, rounded UP
              // to the nearest GiB (minimum 1 GiB). nitro-cli enforces its own minimum of
              // ~EIF x4 (error E26); rounding to the *nearest* GiB can land just below
              // that minimum, so we round UP (ceiling) to guarantee sufficiency.
              'EIF_BYTES=$(stat -c %s attestation-enclave.eif)',
              'NEED_MIB=$(( EIF_BYTES * 4 / 1048576 ))',
              'MEM_MIB=$(( ((NEED_MIB + 1023) / 1024) * 1024 ))',
              'if [ "$MEM_MIB" -lt 1024 ]; then MEM_MIB=1024; fi',
              'echo "EIF=${EIF_BYTES} bytes; x4=${NEED_MIB} MiB; enclave memory (ceil to GiB)=${MEM_MIB} MiB"',
              // Create metadata file with PCR values and resource requirements.
              'jq -n --argjson cpu 1 --argjson mem "$MEM_MIB" --slurpfile build build-output.json \'{cpu_count: $cpu, memory_mib: $mem} + $build[0]\' > metadata.json',
              'cat metadata.json',
              'cd $CODEBUILD_SRC_DIR',
            ],
          },
          post_build: {
            commands: [
              'echo "Creating deployment artifact..."',
              // Create deployment artifact directory structure
              'mkdir -p artifact/enclave',
              'mkdir -p artifact/proxies',
              'mkdir -p artifact/systemd',
              'mkdir -p artifact/deploy/scripts',
              // Copy EIF and metadata
              'cp enclave/attestation-enclave.eif artifact/enclave/',
              'cp enclave/metadata.json artifact/enclave/',
              // Copy enclave shared code
              'cp -r enclave/shared artifact/enclave/',
              // Copy proxy code
              'cp -r proxies/* artifact/proxies/',
              // Copy systemd services
              'cp systemd/*.service artifact/systemd/',
              // Copy deploy scripts and appspec
              'cp deploy/appspec.yml artifact/',
              'cp -r deploy/scripts/* artifact/deploy/scripts/',
              'chmod +x artifact/deploy/scripts/*.sh',
              // List artifact contents
              'echo "Deployment artifact contents:"',
              'find artifact -type f',
              'echo "Build complete!"',
            ],
          },
        },
        artifacts: {
          'base-directory': 'artifact',
          files: ['**/*'],
          'discard-paths': 'no',
        },
      }),
    });

    // ==================== cdk-nag Acknowledgements ====================
    // CDK CodeBuild L2 generates log group and report group resources with :* and -* suffixes.
    // Pipeline also grants this role S3/KMS access via grant*() with wildcard actions.
    const region = cdk.Stack.of(this).region;
    const account = cdk.Stack.of(this).account;
    const buildProjectNode = this.buildProject.node.defaultChild as cdk.CfnResource;
    const buildProjectLogicalId = cdk.Stack.of(this).getLogicalId(buildProjectNode);

    const nagRules: Record<string, string> = {};
    nagRules[`AwsSolutions-IAM5[Resource::arn:aws:logs:${region}:${account}:log-group:/aws/codebuild/<${buildProjectLogicalId}>:*]`] =
      'CDK CodeBuild L2 generates log group ARN with :* suffix for log streams';
    nagRules[`AwsSolutions-IAM5[Resource::arn:aws:codebuild:${region}:${account}:report-group/<${buildProjectLogicalId}>-*]`] =
      'CDK CodeBuild L2 generates report group ARN with -* suffix for report names';
    // Pipeline L2 grants these wildcard S3/KMS actions to the CodeBuild role for artifact access
    nagRules['AwsSolutions-IAM5[Action::s3:Abort*]'] =
      'CDK Pipeline L2 grants wildcard S3 actions for artifact management';
    nagRules['AwsSolutions-IAM5[Action::s3:DeleteObject*]'] =
      'CDK Pipeline L2 grants wildcard S3 actions for artifact management';
    nagRules['AwsSolutions-IAM5[Action::s3:GetBucket*]'] =
      'CDK Pipeline L2 grants wildcard S3 actions for artifact management';
    nagRules['AwsSolutions-IAM5[Action::s3:GetObject*]'] =
      'CDK Pipeline L2 grants wildcard S3 actions for artifact management';
    nagRules['AwsSolutions-IAM5[Action::s3:List*]'] =
      'CDK Pipeline L2 grants wildcard S3 actions for artifact management';
    nagRules['AwsSolutions-IAM5[Action::kms:GenerateDataKey*]'] =
      'CDK Pipeline L2 grants wildcard KMS actions for encrypted artifact bucket';
    nagRules['AwsSolutions-IAM5[Action::kms:ReEncrypt*]'] =
      'CDK Pipeline L2 grants wildcard KMS actions for encrypted artifact bucket';
    cdk.Stack.of(this).node.addMetadata('aws:cdk:acknowledged-rules', nagRules);
  }
}
