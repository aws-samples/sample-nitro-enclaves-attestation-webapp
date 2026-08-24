import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as apigatewayv2 from 'aws-cdk-lib/aws-apigatewayv2';
import { Construct } from 'constructs';

export interface NetworkingProps {
  readonly envName?: string;
  readonly userPoolId?: string;
  readonly userPoolClientId?: string;
}

export class Networking extends Construct {
  public readonly vpc: ec2.Vpc;
  public readonly nlb: elbv2.NetworkLoadBalancer;
  public readonly nlbListener: elbv2.NetworkListener;
  public readonly httpApi: apigatewayv2.CfnApi;
  public readonly vpcLink: apigatewayv2.CfnVpcLink;
  public readonly ec2SecurityGroup: ec2.SecurityGroup;
  public readonly vpcEndpointSecurityGroup: ec2.SecurityGroup;

  constructor(scope: Construct, id: string, props: NetworkingProps = {}) {
    super(scope, id);

    // ==================== VPC (Fully Private) ====================
    // No public subnets, no NAT Gateway - use VPC Endpoints for AWS service access
    this.vpc = new ec2.Vpc(this, 'Vpc', {
      maxAzs: 2,
      natGateways: 0, // No NAT Gateway - fully private
      subnetConfiguration: [
        {
          name: 'Private',
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 24,
        },
      ],
    });

    // ==================== Security Groups ====================
    
    // Security group for VPC Endpoints
    this.vpcEndpointSecurityGroup = new ec2.SecurityGroup(this, 'VpcEndpointSg', {
      vpc: this.vpc,
      description: 'Security group for VPC Endpoints',
      allowAllOutbound: true,
    });

    // Allow HTTPS from within VPC for VPC endpoints
    this.vpcEndpointSecurityGroup.addIngressRule(
      ec2.Peer.ipv4(this.vpc.vpcCidrBlock),
      ec2.Port.tcp(443),
      'Allow HTTPS from VPC for endpoints'
    );

    // Security group for EC2
    this.ec2SecurityGroup = new ec2.SecurityGroup(this, 'Ec2Sg', {
      vpc: this.vpc,
      description: 'Security group for Nitro Enclave EC2 instance',
      allowAllOutbound: true,
    });

    // Allow NLB health checks and traffic from VPC
    this.ec2SecurityGroup.addIngressRule(
      ec2.Peer.ipv4(this.vpc.vpcCidrBlock),
      ec2.Port.tcp(8000),
      'Allow backend API from VPC'
    );

    // ==================== VPC Endpoints (Private AWS Service Access) ====================
    
    // S3 Gateway Endpoint (free, no interface charges)
    this.vpc.addGatewayEndpoint('S3Endpoint', {
      service: ec2.GatewayVpcEndpointAwsService.S3,
      subnets: [{ subnetType: ec2.SubnetType.PRIVATE_ISOLATED }],
    });

    // SSM Endpoints for Session Manager access
    this.vpc.addInterfaceEndpoint('SsmEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.SSM,
      securityGroups: [this.vpcEndpointSecurityGroup],
      subnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
    });

    this.vpc.addInterfaceEndpoint('SsmMessagesEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES,
      securityGroups: [this.vpcEndpointSecurityGroup],
      subnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
    });

    this.vpc.addInterfaceEndpoint('Ec2MessagesEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES,
      securityGroups: [this.vpcEndpointSecurityGroup],
      subnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
    });

    // CloudWatch Logs Endpoint
    this.vpc.addInterfaceEndpoint('CloudWatchLogsEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
      securityGroups: [this.vpcEndpointSecurityGroup],
      subnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
    });

    // STS Endpoint (for IAM credential retrieval)
    this.vpc.addInterfaceEndpoint('StsEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.STS,
      securityGroups: [this.vpcEndpointSecurityGroup],
      subnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
    });

    // EC2 Endpoint (for EC2 API calls)
    this.vpc.addInterfaceEndpoint('Ec2Endpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.EC2,
      securityGroups: [this.vpcEndpointSecurityGroup],
      subnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
    });

    // CodeDeploy Endpoints (required for CodeDeploy agent in isolated subnet)
    this.vpc.addInterfaceEndpoint('CodeDeployEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.CODEDEPLOY,
      securityGroups: [this.vpcEndpointSecurityGroup],
      subnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
    });

    this.vpc.addInterfaceEndpoint('CodeDeployCommandsEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.CODEDEPLOY_COMMANDS_SECURE,
      securityGroups: [this.vpcEndpointSecurityGroup],
      subnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
    });

    // ==================== Network Load Balancer ====================
    this.nlb = new elbv2.NetworkLoadBalancer(this, 'Nlb', {
      vpc: this.vpc,
      internetFacing: false,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
    });

    this.nlbListener = this.nlb.addListener('Listener', {
      port: 80,
    });

    // ==================== API Gateway with VPC Link ====================
    this.vpcLink = new apigatewayv2.CfnVpcLink(this, 'VpcLink', {
      name: 'nitro-attestation-vpc-link',
      subnetIds: this.vpc.isolatedSubnets.map(s => s.subnetId),
      securityGroupIds: [this.ec2SecurityGroup.securityGroupId],
    });

    this.httpApi = new apigatewayv2.CfnApi(this, 'HttpApi', {
      name: 'nitro-attestation-api',
      protocolType: 'HTTP',
      corsConfiguration: {
        allowOrigins: ['*'],
        allowMethods: ['GET', 'POST', 'OPTIONS'],
        allowHeaders: ['*'],
      },
    });

    const integration = new apigatewayv2.CfnIntegration(this, 'NlbIntegration', {
      apiId: this.httpApi.ref,
      integrationType: 'HTTP_PROXY',
      integrationMethod: 'ANY',
      integrationUri: this.nlbListener.listenerArn,
      connectionType: 'VPC_LINK',
      connectionId: this.vpcLink.ref,
      payloadFormatVersion: '1.0',
    });

    // ==================== JWT Authorizer (Cognito) ====================
    let authorizerId: string | undefined;
    if (props.userPoolId && props.userPoolClientId) {
      const region = cdk.Stack.of(this).region;
      const authorizer = new apigatewayv2.CfnAuthorizer(this, 'JwtAuthorizer', {
        apiId: this.httpApi.ref,
        authorizerType: 'JWT',
        name: 'cognito-jwt-authorizer',
        identitySource: ['$request.header.Authorization'],
        jwtConfiguration: {
          audience: [props.userPoolClientId],
          issuer: `https://cognito-idp.${region}.amazonaws.com/${props.userPoolId}`,
        },
      });
      authorizerId = authorizer.ref;
    }

    // $default route WITHOUT auth — acts as fallback for unmatched routes (including OPTIONS).
    // The built-in corsConfiguration responds to OPTIONS preflight via this route.
    // API routes below have explicit JWT auth.
    new apigatewayv2.CfnRoute(this, 'DefaultRoute', {
      apiId: this.httpApi.ref,
      routeKey: '$default',
      target: `integrations/${integration.ref}`,
      authorizationType: 'NONE',
    });

    // Use specific method routes instead of ANY to prevent OPTIONS from matching.
    // This allows the built-in corsConfiguration to handle OPTIONS preflight at the gateway level.
    new apigatewayv2.CfnRoute(this, 'ApiGetRoute', {
      apiId: this.httpApi.ref,
      routeKey: 'GET /api/{proxy+}',
      target: `integrations/${integration.ref}`,
      ...(authorizerId && {
        authorizationType: 'JWT',
        authorizerId,
      }),
    });

    new apigatewayv2.CfnRoute(this, 'ApiPostRoute', {
      apiId: this.httpApi.ref,
      routeKey: 'POST /api/{proxy+}',
      target: `integrations/${integration.ref}`,
      ...(authorizerId && {
        authorizationType: 'JWT',
        authorizerId,
      }),
    });

    new apigatewayv2.CfnStage(this, 'Stage', {
      apiId: this.httpApi.ref,
      stageName: '$default',
      autoDeploy: true,
    });

    // ==================== cdk-nag Acknowledgements ====================
    cdk.Validations.of(this).acknowledge({
      id: 'AwsSolutions-APIG4',
      reason: 'OPTIONS route intentionally unauthenticated for CORS preflight requests',
    });
    cdk.Validations.of(this).acknowledge({
      id: 'AwsSolutions-APIG1',
      reason: 'Access logging not needed for sample application',
    });
    cdk.Validations.of(this).acknowledge({
      id: 'AwsSolutions-ELB2',
      reason: 'NLB access logging out of scope for sample app',
    });
    cdk.Validations.of(this).acknowledge({
      id: 'AwsSolutions-VPC7',
      reason: 'VPC flow logging out of scope for sample app',
    });
    cdk.Validations.of(this).acknowledge({
      id: 'AwsSolutions-EC23',
      reason: 'Security groups use VPC CIDR reference; cdk-nag cannot resolve Fn::GetAtt at synth time',
    });
  }

  public getApiEndpoint(region: string): string {
    return `https://${this.httpApi.ref}.execute-api.${region}.amazonaws.com`;
  }
}