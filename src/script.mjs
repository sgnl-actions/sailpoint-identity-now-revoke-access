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
async function revokeAccess(params, sailpointDomain, authToken) {
  const {
    identityId,
    itemType,
    itemId,
    itemComment,
    itemRemoveDate,
    clientMetadata,
    itemClientMetadata
  } = params;

  const url = new URL('/v3/access-requests', `https://${sailpointDomain}`);

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

  // Add optional item client metadata (should be a JSON string)
  if (itemClientMetadata) {
    try {
      // Validate it's valid JSON by parsing
      JSON.parse(itemClientMetadata);
      requestBody.requestedItems[0].clientMetadata = itemClientMetadata;
    } catch {
      console.error('Invalid itemClientMetadata JSON string, skipping');
    }
  }

  // Add optional request-level client metadata
  if (clientMetadata) {
    try {
      // Validate it's valid JSON by parsing
      JSON.parse(clientMetadata);
      requestBody.clientMetadata = clientMetadata;
    } catch {
      console.error('Invalid clientMetadata JSON string, skipping');
    }
  }

  // Ensure auth token has Bearer prefix
  const authHeader = authToken.startsWith('Bearer ') ? authToken : `Bearer ${authToken}`;

  const response = await fetch(url.toString(), {
    method: 'POST',
    headers: {
      'Authorization': authHeader,
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(requestBody)
  });

  return response;
}


export default {
  /**
   * Main execution handler - creates an access request in SailPoint IdentityNow
   * @param {Object} params - Job input parameters
   * @param {string} params.identityId - The ID of the identity requesting access
   * @param {string} params.itemType - Type of access item (ACCESS_PROFILE, ROLE, or ENTITLEMENT)
   * @param {string} params.itemId - The ID of the access item to grant
   * @param {string} params.sailpointDomain - The SailPoint IdentityNow tenant domain
   * @param {string} params.itemComment - Optional comment for the access request
   * @param {string} params.itemRemoveDate - Optional ISO 8601 date when access should be removed
   * @param {string} params.clientMetadata - Optional JSON string of client metadata for the request
   * @param {string} params.itemClientMetadata - Optional JSON string of client metadata for the item
   * @param {Object} context - Execution context with env, secrets, outputs
   * @returns {Object} Job results
   */
  invoke: async (params, context) => {
    const { identityId, itemType, itemId, sailpointDomain } = params;

    console.log(`Starting SailPoint IdentityNow revoke access request for identity: ${identityId}`);
    console.log(`Revoking ${itemType}: ${itemId}`);

    // Validate required inputs
    if (!identityId || typeof identityId !== 'string') {
      throw new Error('Invalid or missing identityId parameter');
    }
    if (!itemType || typeof itemType !== 'string') {
      throw new Error('Invalid or missing itemType parameter');
    }
    if (!['ACCESS_PROFILE', 'ROLE', 'ENTITLEMENT'].includes(itemType)) {
      throw new Error('itemType must be ACCESS_PROFILE, ROLE, or ENTITLEMENT');
    }
    if (!itemId || typeof itemId !== 'string') {
      throw new Error('Invalid or missing itemId parameter');
    }
    if (!sailpointDomain || typeof sailpointDomain !== 'string') {
      throw new Error('Invalid or missing sailpointDomain parameter');
    }

    // Validate SailPoint API token is present
    if (!context.secrets?.SAILPOINT_API_TOKEN) {
      throw new Error('Missing required secret: SAILPOINT_API_TOKEN');
    }

    // Validate required comment for revoke
    if (!params.itemComment || typeof params.itemComment !== 'string') {
      throw new Error('itemComment is required for revoke access requests');
    }

    // Make the API request to create revoke request
    const response = await revokeAccess(
      params,
      sailpointDomain,
      context.secrets.SAILPOINT_API_TOKEN
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
        requestedAt: new Date().toISOString()
      };
    }

    // Handle error responses
    const statusCode = response.status;
    let errorMessage = `Failed to create revoke access request: HTTP ${statusCode}`;

    try {
      const errorBody = await response.json();
      if (errorBody.detailCode) {
        errorMessage = `Failed to create revoke access request: ${errorBody.detailCode} - ${errorBody.trackingId || ''}`;
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
   * Error recovery handler - attempts to recover from retryable errors
   * @param {Object} params - Original params plus error information
   * @param {Object} context - Execution context
   * @returns {Object} Recovery results
   */
  error: async (params, context) => {
    const { error, identityId, itemType, itemId, sailpointDomain } = params;
    const statusCode = error.statusCode;

    console.error(`Revoke access request failed for identity ${identityId}: ${error.message}`);

    // Get configurable backoff times from environment
    const rateLimitBackoffMs = parseInt(context.environment?.RATE_LIMIT_BACKOFF_MS || '30000', 10);
    const serviceErrorBackoffMs = parseInt(context.environment?.SERVICE_ERROR_BACKOFF_MS || '10000', 10);

    // Handle rate limiting (429)
    if (statusCode === 429 || error.message.includes('429') || error.message.includes('rate limit')) {
      console.log(`Rate limited by SailPoint API - waiting ${rateLimitBackoffMs}ms before retry`);
      await new Promise(resolve => setTimeout(resolve, rateLimitBackoffMs));

      console.log(`Retrying revoke access request for identity ${identityId} after rate limit backoff`);

      // Retry the operation using helper function
      const retryResponse = await revokeAccess(
        params,
        sailpointDomain,
        context.secrets.SAILPOINT_API_TOKEN
      );

      if (retryResponse.ok) {
        const responseData = await retryResponse.json();
        console.log(`Successfully created revoke access request ${responseData.id} after retry`);

        return {
          requestId: responseData.id,
          identityId: identityId,
          itemType: itemType,
          itemId: itemId,
          status: responseData.status || 'PENDING',
          requestedAt: new Date().toISOString(),
          recoveryMethod: 'rate_limit_retry'
        };
      }
    }

    // Handle temporary service issues (502, 503, 504)
    if ([502, 503, 504].includes(statusCode)) {
      console.log(`SailPoint service temporarily unavailable - waiting ${serviceErrorBackoffMs}ms before retry`);
      await new Promise(resolve => setTimeout(resolve, serviceErrorBackoffMs));

      console.log(`Retrying revoke access request for identity ${identityId} after service interruption`);

      // Retry the operation using helper function
      const retryResponse = await revokeAccess(
        params,
        sailpointDomain,
        context.secrets.SAILPOINT_API_TOKEN
      );

      if (retryResponse.ok) {
        const responseData = await retryResponse.json();
        console.log(`Successfully created revoke access request ${responseData.id} after service recovery`);

        return {
          requestId: responseData.id,
          identityId: identityId,
          itemType: itemType,
          itemId: itemId,
          status: responseData.status || 'PENDING',
          requestedAt: new Date().toISOString(),
          recoveryMethod: 'service_retry'
        };
      }
    }

    // Cannot recover from this error
    console.error(`Unable to recover from error for identity ${identityId}`);
    throw new Error(`Unrecoverable error creating revoke access request for identity ${identityId}: ${error.message}`);
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