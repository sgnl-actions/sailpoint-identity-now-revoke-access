import { getBaseURL, getAuthorizationHeader, resolveJSONPathTemplates} from '@sgnl-actions/utils';

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
    itemRemoveDate
  } = params;

  const url = new URL('/v3/access-requests', baseUrl);

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

  // Add required item comment for revoke requests
  if (!itemComment) {
    throw new Error('itemComment is required for REVOKE_ACCESS requests');
  }
  requestBody.requestedItems[0].comment = itemComment;

  // Add optional remove date (must be in RFC3339 format)
  if (itemRemoveDate) {
    // Parse and re-format to ensure RFC3339 compliance
    const removeDate = new Date(itemRemoveDate);
    if (!isNaN(removeDate.getTime())) {
      requestBody.requestedItems[0].removeDate = removeDate.toISOString();
    }
  }

  // authToken is already formatted as a complete Authorization header value
  const response = await fetch(url.toString(), {
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


export default {
  /**
   * Main execution handler - creates an access revoke request in SailPoint IdentityNow
   * @param {Object} params - Input parameters
   * @param {string} params.identityId - The ID of the identity requesting access revocation (required)
   * @param {string} params.itemType - Type of access item (ACCESS_PROFILE, ROLE, or ENTITLEMENT) (required)
   * @param {string} params.itemId - The ID of the access item to revoke (required)
   * @param {string} params.itemComment - Comment for the access revoke request (required)
   * @param {string} params.address - Optional SailPoint IdentityNow base URL
   * @param {string} params.itemRemoveDate - Optional ISO 8601 date when access should be removed
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
    const jobContext = context.data || {};

    // Resolve JSONPath templates in params
    const { result: resolvedParams, errors } = resolveJSONPathTemplates(params, jobContext);
    if (errors.length > 0) {
     console.warn('Template resolution errors:', errors);
    }

    const { identityId, itemType, itemId } = resolvedParams;

    console.log(`Starting SailPoint IdentityNow revoke access request for identity: ${identityId}`);
    console.log(`Revoking ${itemType}: ${itemId}`);

    if (!['ACCESS_PROFILE', 'ROLE', 'ENTITLEMENT'].includes(itemType)) {
      throw new Error('itemType must be ACCESS_PROFILE, ROLE, or ENTITLEMENT');
    }

    // Get base URL using utility function
    const baseUrl = getBaseURL(resolvedParams, context);

    // Get authorization header
    const authHeader = await getAuthorizationHeader(context);

    // Make the API request to create revoke request
    const response = await revokeAccess(
      resolvedParams,
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