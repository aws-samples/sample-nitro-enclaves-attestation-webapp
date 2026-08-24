import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as apigatewayv2 from 'aws-cdk-lib/aws-apigatewayv2';
import { Construct } from 'constructs';

export interface ApiGatewayProps {
  /**
   * Use existing VPC by ID (for connecting to existing EC2 instance)
   */
  readonly existingVpcId?: string;
  
  /**
   * Use existing VPC object
   */
  readonly vpc?: ec2.IVpc;
  
  /**
   * Private IP of the backend EC2 instance
   * Required when using existingVpcId
   */
  readonly backendPrivateIp?: string;
  
  /**
   * Backend port (default: 8000)
   */
  readonly backendPort?: number;
  
  /**
   * Existing NLB listener (if backend stack already created one)
   */
  readonly existingNlbListener?: elbv2.INetworkListener;
  
  /**
   * Subnet IDs for NLB (required when using existingVpcId)
   */
  readonly subnetIds?: string[];
}

/**
 * API Gateway with VPC Link construct
 * 
 * Flexible construct that can:
 * 1. Use an existing VPC and create NLB + API Gateway (for testing with existing EC2)
 * 2. Use a provided NLB listener (from backend stack)
 * 3. Create everything new
 */
export class ApiGateway extends Construct {
  public readonly httpApi: apigatewayv2.CfnApi;
  public readonly vpcLink: apigatewayv2.CfnVpcLink;
  public readonly nlb?: elbv2.NetworkLoadBalancer;
  public readonly apiEndpoint: string;

  constructor(scope: Construct, id: string, props: ApiGatewayProps = {}) {
    super(scope, id);

    const backendPort = props.backendPort || 8000;
    
    // Determine VPC
    let vpc: ec2.IVpc;
    if (props.vpc) {
      vpc = props.vpc;
    } else if (props.existingVpcId) {
      vpc = ec2.Vpc.fromLookup(this, 'ExistingVpc', {
        vpcId: props.existingVpcId,
      });
    } else {
      throw new Error('Either vpc or existingVpcId must be provided');
    }

    // Get or create NLB
    let nlbArn: string;
    
    if (props.existingNlbListener) {
      // Use existing NLB from backend stack
      nlbArn = cdk.Fn.select(0, cdk.Fn.split('/listener/', props.existingNlbListener.listenerArn));
      nlbArn = cdk.Fn.join('', ['arn:aws:elasticloadbalancing:', cdk.Aws.REGION, ':', cdk.Aws.ACCOUNT_ID, ':loadbalancer/', 
        cdk.Fn.select(1, cdk.Fn.split(':loadbalancer/', nlbArn))]);
    } else if (props.backendPrivateIp) {
      // Create new NLB pointing to the existing EC2 instance
      this.nlb = this.createNlb(vpc, props.backendPrivateIp, backendPort, props.subnetIds);
      nlbArn = this.nlb.loadBalancerArn;
    } else {
      throw new Error('Either existingNlbListener or backendPrivateIp must be provided');
    }

    // Create security group for VPC Link
    const vpcLinkSg = new ec2.SecurityGroup(this, 'VpcLinkSecurityGroup', {
      vpc,
      description: 'Security group for API Gateway VPC Link',
      allowAllOutbound: true,
    });

    // Create VPC Link
    this.vpcLink = new apigatewayv2.CfnVpcLink(this, 'VpcLink', {
      name: 'attestation-api-vpc-link',
      subnetIds: props.subnetIds || vpc.privateSubnets.map(s => s.subnetId),
      securityGroupIds: [vpcLinkSg.securityGroupId],
    });

    // Create HTTP API
    this.httpApi = new apigatewayv2.CfnApi(this, 'HttpApi', {
      name: 'attestation-api',
      protocolType: 'HTTP',
      corsConfiguration: {
        allowOrigins: ['*'],
        allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowHeaders: ['*'],
        maxAge: 86400,
      },
    });

    // Create integration with NLB via VPC Link
    const integration = new apigatewayv2.CfnIntegration(this, 'NlbIntegration', {
      apiId: this.httpApi.ref,
      integrationType: 'HTTP_PROXY',
      integrationMethod: 'ANY',
      integrationUri: props.existingNlbListener?.listenerArn || this.nlbListener!.listenerArn,
      connectionType: 'VPC_LINK',
      connectionId: this.vpcLink.ref,
      payloadFormatVersion: '1.0',
    });

    // Create catch-all route
    new apigatewayv2.CfnRoute(this, 'DefaultRoute', {
      apiId: this.httpApi.ref,
      routeKey: '$default',
      target: `integrations/${integration.ref}`,
    });

    // Create stage
    new apigatewayv2.CfnStage(this, 'DefaultStage', {
      apiId: this.httpApi.ref,
      stageName: '$default',
      autoDeploy: true,
    });

    // Set API endpoint
    this.apiEndpoint = `https://${this.httpApi.ref}.execute-api.${cdk.Aws.REGION}.amazonaws.com`;
  }

  public nlbListener?: elbv2.NetworkListener;

  private createNlb(
    vpc: ec2.IVpc, 
    backendIp: string, 
    backendPort: number,
    subnetIds?: string[]
  ): elbv2.NetworkLoadBalancer {
    // Create NLB
    const nlb = new elbv2.NetworkLoadBalancer(this, 'NLB', {
      vpc,
      internetFacing: false,
      vpcSubnets: subnetIds 
        ? { subnets: subnetIds.map((id, i) => ec2.Subnet.fromSubnetId(this, `Subnet${i}`, id)) }
        : { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    // Create target group with IP target
    const targetGroup = new elbv2.NetworkTargetGroup(this, 'BackendTargetGroup', {
      vpc,
      port: backendPort,
      protocol: elbv2.Protocol.TCP,
      targetType: elbv2.TargetType.IP,
      healthCheck: {
        enabled: true,
        protocol: elbv2.Protocol.HTTP,
        path: '/health',
        interval: cdk.Duration.seconds(30),
        healthyThresholdCount: 2,
        unhealthyThresholdCount: 2,
      },
    });

    // Add the EC2 instance IP as target
    targetGroup.addTarget(new IpTarget(backendIp, backendPort));

    // Create listener and store reference
    this.nlbListener = nlb.addListener('Listener', {
      port: 80,
      defaultTargetGroups: [targetGroup],
    });

    return nlb;
  }
}

/**
 * IP Target for NLB
 */
class IpTarget implements elbv2.INetworkLoadBalancerTarget {
  constructor(
    private readonly ipAddress: string,
    private readonly port: number
  ) {}

  attachToNetworkTargetGroup(targetGroup: elbv2.INetworkTargetGroup): elbv2.LoadBalancerTargetProps {
    return {
      targetType: elbv2.TargetType.IP,
      targetJson: {
        id: this.ipAddress,
        port: this.port,
      },
    };
  }
}