import * as cdk from 'aws-cdk-lib';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';
import * as codedeploy from 'aws-cdk-lib/aws-codedeploy';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export interface CodeDeployProps {
  readonly asg: autoscaling.AutoScalingGroup;
  readonly ec2Role: iam.Role;
}

export class CodeDeployApplication extends Construct {
  public readonly application: codedeploy.ServerApplication;
  public readonly deploymentGroup: codedeploy.ServerDeploymentGroup;

  constructor(scope: Construct, id: string, props: CodeDeployProps) {
    super(scope, id);

    // Add CodeDeploy agent permissions to EC2 role
    props.ec2Role.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonEC2RoleforAWSCodeDeploy')
    );

    // Create CodeDeploy Application
    this.application = new codedeploy.ServerApplication(this, 'Application', {
      applicationName: 'nitro-attestation-app',
    });

    // Create Deployment Group targeting the ASG
    this.deploymentGroup = new codedeploy.ServerDeploymentGroup(this, 'DeploymentGroup', {
      application: this.application,
      deploymentGroupName: 'nitro-attestation-deployment-group',
      autoScalingGroups: [props.asg],
      deploymentConfig: codedeploy.ServerDeploymentConfig.ALL_AT_ONCE,
      autoRollback: {
        failedDeployment: true,
        stoppedDeployment: true,
      },
      installAgent: false, // We install via user data for isolated subnet
    });

    // ==================== cdk-nag Acknowledgements ====================
    const nagRules: Record<string, string> = {};
    nagRules['AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSCodeDeployRole]'] =
      'AWS managed policy required for CodeDeploy service role to manage deployments';
    cdk.Stack.of(this).node.addMetadata('aws:cdk:acknowledged-rules', nagRules);
  }
}
