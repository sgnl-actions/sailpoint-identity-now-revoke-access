import script from '../src/script.mjs';

describe('SailPoint IdentityNow Revoke Access Script', () => {
  const mockContext = {
    env: {
      ENVIRONMENT: 'test'
    },
    secrets: {
      SAILPOINT_API_TOKEN: 'test-sailpoint-token-123456'
    },
    outputs: {}
  };

  let originalFetch;
  let originalURL;
  let fetchMock;

  beforeAll(() => {
    // Save original global functions
    originalFetch = global.fetch;
    originalURL = global.URL;
  });

  beforeEach(() => {
    // Create a fresh mock for each test
    fetchMock = () => Promise.resolve({
      ok: true,
      status: 202,
      json: async () => ({
        id: 'request-123',
        requestedFor: [{ id: 'identity-456' }],
        requestedItems: [{
          id: 'item-789',
          type: 'ACCESS_PROFILE',
          name: 'Test Access Profile'
        }]
      })
    });
    
    // Set up global mocks
    global.fetch = fetchMock;
    global.URL = originalURL || class {
      constructor(path, base) {
        this.href = base ? `${base.replace(/\/$/, '')}${path}` : path;
      }
      toString() {
        return this.href;
      }
    };
    
    // Mock console to avoid noise in tests
    global.console.log = () => {};
    global.console.error = () => {};
  });

  afterAll(() => {
    // Restore original global functions
    global.fetch = originalFetch;
    global.URL = originalURL;
  });

  describe('invoke handler', () => {
    test('should successfully create revoke access request', async () => {
      const params = {
        identityId: 'identity-456',
        itemType: 'ACCESS_PROFILE',
        itemId: 'ap-789',
        sailpointDomain: 'test.identitynow.com',
        itemComment: 'Access revocation required'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.requestId).toBe('request-123');
      expect(result.identityId).toBe('identity-456');
      expect(result.itemType).toBe('ACCESS_PROFILE');
      expect(result.itemId).toBe('ap-789');
      expect(result.status).toBe('PENDING');
      expect(result.requestedAt).toBeDefined();
      
      // Basic verification that result is returned
      // Note: Without jest.fn() we can't verify call details
    });

    test('should handle revoke access request with comment', async () => {
      const params = {
        identityId: 'identity-456',
        itemType: 'ROLE',
        itemId: 'role-123',
        sailpointDomain: 'test.identitynow.com',
        itemComment: 'Access revocation required',
        comment: 'Needed for project X'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.requestId).toBe('request-123');
      expect(result.requestedAt).toBeDefined();
      
      // Basic verification that result is returned with comment
      // Note: Without jest.fn() we can't verify request details
    });

    test('should handle entitlement revoke request', async () => {
      const params = {
        identityId: 'identity-456',
        itemType: 'ENTITLEMENT',
        itemId: 'ent-999',
        sailpointDomain: 'test.identitynow.com',
        itemComment: 'Access revocation required'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.itemType).toBe('ENTITLEMENT');
      expect(result.itemId).toBe('ent-999');
      expect(result.requestedAt).toBeDefined();
    });

    test('should throw error for missing identityId', async () => {
      const params = {
        itemType: 'ACCESS_PROFILE',
        itemId: 'ap-789',
        sailpointDomain: 'test.identitynow.com',
        itemComment: 'Access revocation required'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('Invalid or missing identityId parameter');
    });

    test('should throw error for invalid itemType', async () => {
      const params = {
        identityId: 'identity-456',
        itemType: 'INVALID_TYPE',
        itemId: 'ap-789',
        sailpointDomain: 'test.identitynow.com',
        itemComment: 'Access revocation required'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('itemType must be ACCESS_PROFILE, ROLE, or ENTITLEMENT');
    });

    test('should throw error for missing itemId', async () => {
      const params = {
        identityId: 'identity-456',
        itemType: 'ACCESS_PROFILE',
        sailpointDomain: 'test.identitynow.com',
        itemComment: 'Access revocation required'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('Invalid or missing itemId parameter');
    });

    test('should throw error for missing sailpointDomain', async () => {
      const params = {
        identityId: 'identity-456',
        itemType: 'ACCESS_PROFILE',
        itemId: 'ap-789'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('Invalid or missing sailpointDomain parameter');
    });

    test('should throw error for missing API token', async () => {
      const params = {
        identityId: 'identity-456',
        itemType: 'ACCESS_PROFILE',
        itemId: 'ap-789',
        sailpointDomain: 'test.identitynow.com',
        itemComment: 'Access revocation required'
      };
      
      const contextNoToken = {
        ...mockContext,
        secrets: {}
      };

      await expect(script.invoke(params, contextNoToken)).rejects.toThrow('Missing required secret: SAILPOINT_API_TOKEN');
    });

    test('should handle API error response', async () => {
      global.fetch = () => Promise.resolve({
        ok: false,
        status: 400,
        json: async () => ({
          detailCode: '400.1',
          messages: [{ text: 'Invalid identity ID provided' }]
        })
      });

      const params = {
        identityId: 'invalid-id',
        itemType: 'ACCESS_PROFILE',
        itemId: 'ap-789',
        sailpointDomain: 'test.identitynow.com',
        itemComment: 'Access revocation required'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('Failed to create revoke access request: 400.1');
    });

    test('should handle rate limit error', async () => {
      global.fetch = () => Promise.resolve({
        ok: false,
        status: 429,
        headers: new Map([['Retry-After', '60']]),
        json: async () => ({
          message: 'Rate limit exceeded'
        })
      });

      const params = {
        identityId: 'identity-456',
        itemType: 'ACCESS_PROFILE',
        itemId: 'ap-789',
        sailpointDomain: 'test.identitynow.com',
        itemComment: 'Access revocation required'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('Rate limit exceeded');
    });
  });

  describe('error handler', () => {
    test('should retry on rate limit error', async () => {
      const errorWithStatus = new Error('API rate limit exceeded');
      errorWithStatus.statusCode = 429;
      
      const params = {
        error: errorWithStatus,
        identityId: 'identity-456',
        itemType: 'ACCESS_PROFILE',
        itemId: 'ap-789',
        sailpointDomain: 'test.identitynow.com',
        itemComment: 'Access revocation required'
      };

      // Mock successful retry
      global.fetch = () => Promise.resolve({
        ok: true,
        status: 202,
        json: async () => ({
          id: 'request-retry-123'
        })
      });

      const contextWithShortBackoff = {
        ...mockContext,
        environment: {
          RATE_LIMIT_BACKOFF_MS: '100' // Short backoff for testing
        }
      };

      const result = await script.error(params, contextWithShortBackoff);

      // The error handler should successfully recover
      expect(result.requestId).toBe('request-retry-123');
      expect(result.recoveryMethod).toBe('rate_limit_retry');
    }, 10000); // Increase test timeout

    test('should throw for non-retryable errors', async () => {
      const params = {
        error: new Error('Invalid credentials'),
        identityId: 'identity-456'
      };

      await expect(script.error(params, mockContext)).rejects.toThrow('Unrecoverable error creating revoke access request for identity identity-456: Invalid credentials');
    });
  });

  describe('halt handler', () => {
    test('should handle graceful shutdown', async () => {
      const params = {
        identityId: 'identity-456'
      };
      
      const result = await script.halt(params, mockContext);
      
      expect(result.cleanupCompleted).toBe(true);
      expect(result.haltedAt).toBeDefined();
    });
  });
});