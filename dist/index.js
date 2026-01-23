// SGNL Job Script - Auto-generated bundle
'use strict';

/**
 * SGNL Actions - Authentication Utilities
 *
 * Shared authentication utilities for SGNL actions.
 * Supports: Bearer Token, Basic Auth, OAuth2 Client Credentials, OAuth2 Authorization Code
 */

/**
 * Get OAuth2 access token using client credentials flow
 * @param {Object} config - OAuth2 configuration
 * @param {string} config.tokenUrl - Token endpoint URL
 * @param {string} config.clientId - Client ID
 * @param {string} config.clientSecret - Client secret
 * @param {string} [config.scope] - OAuth2 scope
 * @param {string} [config.audience] - OAuth2 audience
 * @param {string} [config.authStyle] - Auth style: 'InParams' or 'InHeader' (default)
 * @returns {Promise<string>} Access token
 */
async function getClientCredentialsToken(config) {
  const { tokenUrl, clientId, clientSecret, scope, audience, authStyle } = config;

  if (!tokenUrl || !clientId || !clientSecret) {
    throw new Error('OAuth2 Client Credentials flow requires tokenUrl, clientId, and clientSecret');
  }

  const params = new URLSearchParams();
  params.append('grant_type', 'client_credentials');

  if (scope) {
    params.append('scope', scope);
  }

  if (audience) {
    params.append('audience', audience);
  }

  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'
  };

  if (authStyle === 'InParams') {
    params.append('client_id', clientId);
    params.append('client_secret', clientSecret);
  } else {
    const credentials = btoa(`${clientId}:${clientSecret}`);
    headers['Authorization'] = `Basic ${credentials}`;
  }

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers,
    body: params.toString()
  });

  if (!response.ok) {
    let errorText;
    try {
      const errorData = await response.json();
      errorText = JSON.stringify(errorData);
    } catch {
      errorText = await response.text();
    }
    throw new Error(
      `OAuth2 token request failed: ${response.status} ${response.statusText} - ${errorText}`
    );
  }

  const data = await response.json();

  if (!data.access_token) {
    throw new Error('No access_token in OAuth2 response');
  }

  return data.access_token;
}

/**
 * Get the Authorization header value from context using available auth method.
 * Supports: Bearer Token, Basic Auth, OAuth2 Authorization Code, OAuth2 Client Credentials
 *
 * @param {Object} context - Execution context with environment and secrets
 * @param {Object} context.environment - Environment variables
 * @param {Object} context.secrets - Secret values
 * @returns {Promise<string>} Authorization header value (e.g., "Bearer xxx" or "Basic xxx")
 */
async function getAuthorizationHeader(context) {
  const env = context.environment || {};
  const secrets = context.secrets || {};

  // Method 1: Simple Bearer Token
  if (secrets.BEARER_AUTH_TOKEN) {
    const token = secrets.BEARER_AUTH_TOKEN;
    return token.startsWith('Bearer ') ? token : `Bearer ${token}`;
  }

  // Method 2: Basic Auth (username + password)
  if (secrets.BASIC_PASSWORD && secrets.BASIC_USERNAME) {
    const credentials = btoa(`${secrets.BASIC_USERNAME}:${secrets.BASIC_PASSWORD}`);
    return `Basic ${credentials}`;
  }

  // Method 3: OAuth2 Authorization Code - use pre-existing access token
  if (secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN) {
    const token = secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN;
    return token.startsWith('Bearer ') ? token : `Bearer ${token}`;
  }

  // Method 4: OAuth2 Client Credentials - fetch new token
  if (secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET) {
    const tokenUrl = env.OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL;
    const clientId = env.OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID;
    const clientSecret = secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET;

    if (!tokenUrl || !clientId) {
      throw new Error('OAuth2 Client Credentials flow requires TOKEN_URL and CLIENT_ID in env');
    }

    const token = await getClientCredentialsToken({
      tokenUrl,
      clientId,
      clientSecret,
      scope: env.OAUTH2_CLIENT_CREDENTIALS_SCOPE,
      audience: env.OAUTH2_CLIENT_CREDENTIALS_AUDIENCE,
      authStyle: env.OAUTH2_CLIENT_CREDENTIALS_AUTH_STYLE
    });

    return `Bearer ${token}`;
  }

  throw new Error(
    'No authentication configured. Provide one of: ' +
    'BEARER_AUTH_TOKEN, BASIC_USERNAME/BASIC_PASSWORD, ' +
    'OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN, or OAUTH2_CLIENT_CREDENTIALS_*'
  );
}

/**
 * Get the base URL/address for API calls
 * @param {Object} params - Request parameters
 * @param {string} [params.address] - Address from params
 * @param {Object} context - Execution context
 * @returns {string} Base URL
 */
function getBaseURL(params, context) {
  const env = context.environment || {};
  const address = params?.address || env.ADDRESS;

  if (!address) {
    throw new Error('No URL specified. Provide address parameter or ADDRESS environment variable');
  }

  // Remove trailing slash if present
  return address.endsWith('/') ? address.slice(0, -1) : address;
}

/**
 * SailPoint IdentityNow Revoke Access Action
 *
 * Creates an access request in SailPoint IdentityNow to revoke access to roles,
 * access profiles, or entitlements for a specified identity.
 */

/**
 * Helper function to create an access request in SailPoint IdentityNow
 * @private
 */
async function revokeAccess(params, baseUrl, authToken) {
  const {
    identityId,
    itemType,
    itemId,
    itemComment,
    itemRemoveDate,
    clientMetadata,
    itemClientMetadata
  } = params;

  const url = `${baseUrl}/v3/access-requests`;

  // Build request body according to SailPoint API spec
  const requestBody = {
    requestedFor: [identityId],
    requestType: 'REVOKE_ACCESS',
    requestedItems: [
      {
        type: itemType,
        id: itemId
      }
    ]
  };

  // Add optional client metadata at request level
  if (clientMetadata) {
    requestBody.clientMetadata = clientMetadata;
  }

  // Add required item comment for revoke requests
  if (!itemComment) {
    throw new Error('itemComment is required for REVOKE_ACCESS requests');
  }
  requestBody.requestedItems[0].comment = itemComment;

  // Add optional item client metadata
  if (itemClientMetadata) {
    requestBody.requestedItems[0].clientMetadata = itemClientMetadata;
  }

  // Add optional remove date (must be in RFC3339 format)
  if (itemRemoveDate) {
    // Parse and re-format to ensure RFC3339 compliance
    const removeDate = new Date(itemRemoveDate);
    if (!isNaN(removeDate.getTime())) {
      requestBody.requestedItems[0].removeDate = removeDate.toISOString();
    }
  }

  // authToken is already formatted as a complete Authorization header value
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': authToken,
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(requestBody)
  });

  return response;
}

var script = {
  /**
   * Main execution handler - creates an access revoke request in SailPoint IdentityNow
   * @param {Object} params - Input parameters
   * @param {string} params.identityId - The ID of the identity requesting access revocation (required)
   * @param {string} params.itemType - Type of access item (ACCESS_PROFILE, ROLE, or ENTITLEMENT) (required)
   * @param {string} params.itemId - The ID of the access item to revoke (required)
   * @param {string} params.itemComment - Comment for the access revoke request (required)
   * @param {string} params.address - Optional SailPoint IdentityNow base URL
   * @param {string} params.itemRemoveDate - Optional ISO 8601 date when access should be removed
   * @param {string} params.clientMetadata - Optional arbitrary key-value pairs as JSON string
   * @param {string} params.itemClientMetadata - Optional arbitrary key-value pairs as JSON string
   *
   * @param {Object} context - Execution context with secrets and environment
   * @param {string} context.environment.ADDRESS - Default SailPoint IdentityNow API base URL
   *
   * The configured auth type will determine which of the following environment variables and secrets are available
   * @param {string} context.secrets.BEARER_AUTH_TOKEN
   *
   * @param {string} context.secrets.BASIC_USERNAME
   * @param {string} context.secrets.BASIC_PASSWORD
   *
   * @param {string} context.secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_AUDIENCE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_AUTH_STYLE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_SCOPE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL
   *
   * @param {string} context.secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN
   *
   * @returns {Promise<Object>} Action result
   */
  invoke: async (params, context) => {

    const { identityId, itemType, itemId } = params;

    console.log(`Starting SailPoint IdentityNow revoke access request for identity: ${identityId}`);
    console.log(`Revoking ${itemType}: ${itemId}`);

    if (!['ACCESS_PROFILE', 'ROLE', 'ENTITLEMENT'].includes(itemType)) {
      throw new Error('itemType must be ACCESS_PROFILE, ROLE, or ENTITLEMENT');
    }

    // Get base URL using utility function
    const baseUrl = getBaseURL(params, context);

    // Get authorization header
    const authHeader = await getAuthorizationHeader(context);

    // Make the API request to create revoke request
    const response = await revokeAccess(
      params,
      baseUrl,
      authHeader
    );

    // Handle the response
    if (response.ok) {
      // 202 Accepted is the expected success response
      const responseData = await response.json();
      console.log(`Successfully created revoke access request ${responseData.id} for identity ${identityId}`);

      return {
        requestId: responseData.id,
        identityId: identityId,
        itemType: itemType,
        itemId: itemId,
        status: responseData.status || 'PENDING',
        requestedAt: new Date().toISOString(),
        address: baseUrl
      };
    }

    // Handle error responses
    const statusCode = response.status;
    let errorMessage = `Failed to create revoke access request: HTTP ${statusCode}`;

    try {
      const errorBody = await response.json();
      if (errorBody.detailCode) {
        errorMessage = `Failed to create revoke access request: ${errorBody.detailCode} - ${errorBody.trackingId || ''}`;
      } else if (errorBody.messages && errorBody.messages.length > 0) {
        errorMessage = `Failed to create revoke access request: ${errorBody.messages[0].text}`;
      } else if (errorBody.message) {
        errorMessage = `Failed to create revoke access request: ${errorBody.message}`;
      }
      console.error('SailPoint API error response:', errorBody);
    } catch {
      // Response might not be JSON
      const errorText = await response.text();
      if (errorText) {
        errorMessage = `Failed to create revoke access request: ${errorText}`;
      }
      console.error('Failed to parse error response');
    }

    // Throw error with status code for proper error handling
    const error = new Error(errorMessage);
    error.statusCode = statusCode;
    throw error;
  },

  /**
   * Error handler - re-throws errors to let framework handle retry logic
   * @param {Object} params - Original params plus error information
   * @param {Object} context - Execution context
   * @returns {Object} Recovery results
   */
  error: async (params, _context) => {
    const { error } = params;
    // Re-throw error to let framework handle retry logic
    throw error;
  },

  /**
   * Graceful shutdown handler - cleanup when job is halted
   * @param {Object} params - Original params plus halt reason
   * @param {Object} context - Execution context
   * @returns {Object} Cleanup results
   */
  halt: async (params, _context) => {
    const { reason, identityId, itemType, itemId } = params;
    console.log(`Revoke access request job is being halted (${reason}) for identity ${identityId}`);

    // No cleanup needed for this operation
    // The POST request either completed or didn't

    return {
      identityId: identityId || 'unknown',
      itemType: itemType || 'unknown',
      itemId: itemId || 'unknown',
      reason: reason,
      haltedAt: new Date().toISOString(),
      cleanupCompleted: true
    };
  }
};

module.exports = script;
