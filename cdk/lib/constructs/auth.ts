import * as cdk from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import { Construct } from 'constructs';

export interface AuthProps {
  readonly accountId: string;
  readonly region: string;
}

export class Auth extends Construct {
  public readonly userPool: cognito.UserPool;
  public readonly userPoolClient: cognito.UserPoolClient;
  public readonly userPoolDomain: cognito.UserPoolDomain;

  constructor(scope: Construct, id: string, props: AuthProps) {
    super(scope, id);

    // ==================== Cognito User Pool ====================
    this.userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: 'nitro-attestation-users',
      selfSignUpEnabled: true,
      signInAliases: { email: true },
      autoVerify: { email: true },
      passwordPolicy: {
        minLength: 8,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Explicitly set UserPoolTier to LITE so that the legacy AdminCreateUserConfig
    // property (AllowAdminCreateUserOnly: false) is respected by Cognito.
    // Without this, new pools default to ESSENTIALS tier which ignores AdminCreateUserConfig
    // and requires the newer SignUpPolicy property to allow self-signup.
    const cfnUserPool = this.userPool.node.defaultChild as cognito.CfnUserPool;
    cfnUserPool.addPropertyOverride('UserPoolTier', 'LITE');
    // Explicitly ensure self-signup is allowed (AdminCreateUserConfig may default to true)
    cfnUserPool.addPropertyOverride('AdminCreateUserConfig.AllowAdminCreateUserOnly', false);
    // Explicitly set AutoVerifiedAttributes (CDK's autoVerify may not be applied with LITE tier)
    cfnUserPool.addPropertyOverride('AutoVerifiedAttributes', ['email']);

    // ==================== User Pool Client ====================
    this.userPoolClient = new cognito.UserPoolClient(this, 'UserPoolClient', {
      userPool: this.userPool,
      authFlows: {
        userPassword: true,
        userSrp: true,
      },
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.PROFILE,
        ],
        callbackUrls: ['http://localhost:3000/', 'https://localhost:3000/'],
        logoutUrls: ['http://localhost:3000/', 'https://localhost:3000/'],
      },
    });

    // ==================== User Pool Domain ====================
    this.userPoolDomain = new cognito.UserPoolDomain(this, 'UserPoolDomain', {
      userPool: this.userPool,
      cognitoDomain: {
        domainPrefix: `nitro-attestation-${props.accountId}`,
      },
    });

    // ==================== cdk-nag Acknowledgements ====================
    cdk.Validations.of(this).acknowledge({
      id: 'AwsSolutions-COG2',
      reason: 'MFA not required for sample/demo application',
    });
    cdk.Validations.of(this).acknowledge({
      id: 'AwsSolutions-COG8',
      reason: 'Cognito Plus tier not needed for sample application',
    });
  }

  public getCognitoDomainUrl(region: string): string {
    return `https://${this.userPoolDomain.domainName}.auth.${region}.amazoncognito.com`;
  }
}