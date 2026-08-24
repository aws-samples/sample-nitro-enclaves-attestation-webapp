/**
 * Cognito Authentication Helper
 * 
 * Implements real authentication against AWS Cognito User Pool
 */
import {
  CognitoUserPool,
  CognitoUser,
  AuthenticationDetails,
  CognitoUserAttribute,
} from 'amazon-cognito-identity-js';

// Cognito configuration from environment variables (set during build from CDK outputs)
const COGNITO_USER_POOL_ID = import.meta.env.VITE_USER_POOL_ID;
const COGNITO_CLIENT_ID = import.meta.env.VITE_USER_POOL_CLIENT_ID;

if (!COGNITO_USER_POOL_ID || !COGNITO_CLIENT_ID) {
  console.error('Missing Cognito configuration. Ensure VITE_USER_POOL_ID and VITE_USER_POOL_CLIENT_ID are set at build time.');
}

// Create User Pool instance
const userPool = new CognitoUserPool({
  UserPoolId: COGNITO_USER_POOL_ID,
  ClientId: COGNITO_CLIENT_ID,
});

/**
 * Sign in a user with email and password
 * @param {string} email - User's email
 * @param {string} password - User's password
 * @returns {Promise<object>} User data on success
 */
// Store cognitoUser for newPasswordRequired flow
let pendingCognitoUser = null;
let pendingUserAttributes = null;

export async function signIn(email, password, newPassword = null) {
  // If we have a pending user and newPassword, complete the challenge
  if (pendingCognitoUser && newPassword) {
    return completeNewPasswordChallenge(newPassword);
  }

  const cognitoUser = new CognitoUser({
    Username: email.toLowerCase(),
    Pool: userPool,
  });

  const authDetails = new AuthenticationDetails({
    Username: email.toLowerCase(),
    Password: password,
  });

  return new Promise((resolve, reject) => {
    cognitoUser.authenticateUser(authDetails, {
      onSuccess: (result) => {
        pendingCognitoUser = null;
        pendingUserAttributes = null;
        
        const idToken = result.getIdToken().getJwtToken();
        const accessToken = result.getAccessToken().getJwtToken();
        const refreshToken = result.getRefreshToken().getToken();
        
        // Get user attributes
        cognitoUser.getUserAttributes((err, attributes) => {
          if (err) {
            // Still resolve with basic info even if attributes fail
            resolve({
              email: email.toLowerCase(),
              isAuthenticated: true,
              idToken,
              accessToken,
              refreshToken,
            });
            return;
          }
          
          const userAttributes = {};
          if (attributes) {
            attributes.forEach(attr => {
              userAttributes[attr.getName()] = attr.getValue();
            });
          }
          
          resolve({
            email: userAttributes.email || email.toLowerCase(),
            isAuthenticated: true,
            idToken,
            accessToken,
            refreshToken,
            attributes: userAttributes,
          });
        });
      },
      onFailure: (err) => {
        pendingCognitoUser = null;
        pendingUserAttributes = null;
        reject(new Error(err.message || 'Authentication failed'));
      },
      newPasswordRequired: (userAttributes, requiredAttributes) => {
        // Store the user and attributes for later completion
        pendingCognitoUser = cognitoUser;
        pendingUserAttributes = userAttributes;
        
        // Signal that new password is required
        const error = new Error('NEW_PASSWORD_REQUIRED');
        error.code = 'NewPasswordRequired';
        reject(error);
      },
    });
  });
}

/**
 * Complete the new password challenge
 * @param {string} newPassword - The new password to set
 * @returns {Promise<object>} User data on success
 */
export async function completeNewPasswordChallenge(newPassword) {
  if (!pendingCognitoUser) {
    throw new Error('No pending password challenge. Please sign in first.');
  }

  return new Promise((resolve, reject) => {
    // Remove email from attributes as it's not allowed to be changed
    const attributesToSend = { ...pendingUserAttributes };
    delete attributesToSend.email;
    delete attributesToSend.email_verified;

    pendingCognitoUser.completeNewPasswordChallenge(newPassword, attributesToSend, {
      onSuccess: (result) => {
        const email = pendingUserAttributes?.email || pendingCognitoUser.getUsername();
        pendingCognitoUser = null;
        pendingUserAttributes = null;

        const idToken = result.getIdToken().getJwtToken();
        const accessToken = result.getAccessToken().getJwtToken();
        const refreshToken = result.getRefreshToken().getToken();

        resolve({
          email: email,
          isAuthenticated: true,
          idToken,
          accessToken,
          refreshToken,
        });
      },
      onFailure: (err) => {
        reject(new Error(err.message || 'Failed to set new password'));
      },
    });
  });
}

/**
 * Check if there's a pending new password challenge
 */
export function hasPendingPasswordChallenge() {
  return pendingCognitoUser !== null;
}

/**
 * Sign up a new user
 * @param {string} email - User's email
 * @param {string} password - User's password
 * @returns {Promise<object>} Result with user info
 */
export async function signUp(email, password) {
  const attributeList = [
    new CognitoUserAttribute({
      Name: 'email',
      Value: email.toLowerCase(),
    }),
  ];

  return new Promise((resolve, reject) => {
    userPool.signUp(
      email.toLowerCase(),
      password,
      attributeList,
      null,
      (err, result) => {
        if (err) {
          reject(new Error(err.message || 'Sign up failed'));
          return;
        }
        
        resolve({
          user: result.user,
          userConfirmed: result.userConfirmed,
          email: email.toLowerCase(),
        });
      }
    );
  });
}

/**
 * Confirm user sign up with verification code
 * @param {string} email - User's email
 * @param {string} code - Verification code from email
 * @returns {Promise<string>} Success message
 */
export async function confirmSignUp(email, code) {
  const cognitoUser = new CognitoUser({
    Username: email.toLowerCase(),
    Pool: userPool,
  });

  return new Promise((resolve, reject) => {
    cognitoUser.confirmRegistration(code, true, (err, result) => {
      if (err) {
        reject(new Error(err.message || 'Verification failed'));
        return;
      }
      resolve(result);
    });
  });
}

/**
 * Resend verification code
 * @param {string} email - User's email
 * @returns {Promise<object>} Delivery details
 */
export async function resendVerificationCode(email) {
  const cognitoUser = new CognitoUser({
    Username: email.toLowerCase(),
    Pool: userPool,
  });

  return new Promise((resolve, reject) => {
    cognitoUser.resendConfirmationCode((err, result) => {
      if (err) {
        reject(new Error(err.message || 'Failed to resend code'));
        return;
      }
      resolve(result);
    });
  });
}

/**
 * Sign out the current user
 */
export function signOut() {
  const cognitoUser = userPool.getCurrentUser();
  if (cognitoUser) {
    cognitoUser.signOut();
  }
  localStorage.removeItem('nitro_user');
}

/**
 * Get the current authenticated user from session
 * @returns {Promise<object|null>} User data or null
 */
export async function getCurrentUser() {
  const cognitoUser = userPool.getCurrentUser();
  
  if (!cognitoUser) {
    return null;
  }

  return new Promise((resolve) => {
    cognitoUser.getSession((err, session) => {
      if (err || !session || !session.isValid()) {
        resolve(null);
        return;
      }
      
      cognitoUser.getUserAttributes((err, attributes) => {
        if (err) {
          resolve({
            email: cognitoUser.getUsername(),
            isAuthenticated: true,
            idToken: session.getIdToken().getJwtToken(),
          });
          return;
        }
        
        const userAttributes = {};
        if (attributes) {
          attributes.forEach(attr => {
            userAttributes[attr.getName()] = attr.getValue();
          });
        }
        
        resolve({
          email: userAttributes.email || cognitoUser.getUsername(),
          isAuthenticated: true,
          idToken: session.getIdToken().getJwtToken(),
          accessToken: session.getAccessToken().getJwtToken(),
          attributes: userAttributes,
        });
      });
    });
  });
}

/**
 * Forgot password - initiate reset
 * @param {string} email - User's email
 * @returns {Promise<object>} Delivery details
 */
export async function forgotPassword(email) {
  const cognitoUser = new CognitoUser({
    Username: email.toLowerCase(),
    Pool: userPool,
  });

  return new Promise((resolve, reject) => {
    cognitoUser.forgotPassword({
      onSuccess: (data) => resolve(data),
      onFailure: (err) => reject(new Error(err.message || 'Failed to initiate password reset')),
    });
  });
}

/**
 * Confirm forgot password with code and new password
 * @param {string} email - User's email
 * @param {string} code - Verification code
 * @param {string} newPassword - New password
 * @returns {Promise<string>} Success message
 */
export async function confirmForgotPassword(email, code, newPassword) {
  const cognitoUser = new CognitoUser({
    Username: email.toLowerCase(),
    Pool: userPool,
  });

  return new Promise((resolve, reject) => {
    cognitoUser.confirmPassword(code, newPassword, {
      onSuccess: () => resolve('Password reset successful'),
      onFailure: (err) => reject(new Error(err.message || 'Failed to reset password')),
    });
  });
}

export default {
  signIn,
  signUp,
  confirmSignUp,
  resendVerificationCode,
  signOut,
  getCurrentUser,
  forgotPassword,
  confirmForgotPassword,
};