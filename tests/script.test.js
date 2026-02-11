import script from '../src/script.mjs';
import { SGNL_USER_AGENT } from '@sgnl-actions/utils';

describe('SailPoint IdentityNow Revoke Access Script', () => {
  const mockContext = {
    environment: {
      ADDRESS: 'https://test.identitynow.com'
    },
    secrets: {
      BEARER_AUTH_TOKEN: 'test-sailpoint-token-123456'
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

        itemComment: 'Access revocation required'
      };

      let capturedOptions;
      global.fetch = (url, options) => {
        capturedOptions = options;
        return Promise.resolve({
          ok: true,
          status: 202,
          json: async () => ({
            id: 'request-123',
            requestedFor: [{ id: 'identity-456' }],
            requestedItems: [{ id: 'item-789', type: 'ACCESS_PROFILE', name: 'Test Access Profile' }]
          })
        });
      };

      const result = await script.invoke(params, mockContext);

      expect(result.requestId).toBe('request-123');
      expect(result.identityId).toBe('identity-456');
      expect(result.itemType).toBe('ACCESS_PROFILE');
      expect(result.itemId).toBe('ap-789');
      expect(result.status).toBe('PENDING');
      expect(result.requestedAt).toBeDefined();
      expect(capturedOptions.headers['User-Agent']).toBe(SGNL_USER_AGENT);
      
      // Basic verification that result is returned
      // Note: Without jest.fn() we can't verify call details
    });

    test('should handle revoke access request with comment', async () => {
      const params = {
        identityId: 'identity-456',
        itemType: 'ROLE',
        itemId: 'role-123',
        itemComment: 'Access revocation required'
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

        itemComment: 'Access revocation required'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.itemType).toBe('ENTITLEMENT');
      expect(result.itemId).toBe('ent-999');
      expect(result.requestedAt).toBeDefined();
    });

    test('should throw error for invalid itemType', async () => {
      const params = {
        identityId: 'identity-456',
        itemType: 'INVALID_TYPE',
        itemId: 'ap-789',

        itemComment: 'Access revocation required'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('itemType must be ACCESS_PROFILE, ROLE, or ENTITLEMENT');
    });

    test('should throw error for missing address', async () => {
      const params = {
        identityId: 'identity-456',
        itemType: 'ACCESS_PROFILE',
        itemId: 'ap-789',
        itemComment: 'Access revocation required'
      };

      const contextNoAddress = {
        environment: {},
        secrets: { BEARER_AUTH_TOKEN: 'test-token' }
      };

      await expect(script.invoke(params, contextNoAddress)).rejects.toThrow('No URL specified. Provide address parameter or ADDRESS environment variable');
    });

    test('should throw error for missing API token', async () => {
      const params = {
        identityId: 'identity-456',
        itemType: 'ACCESS_PROFILE',
        itemId: 'ap-789',
        itemComment: 'Access revocation required'
      };

      const contextNoToken = {
        environment: { ADDRESS: 'https://test.identitynow.com' },
        secrets: {}
      };

      await expect(script.invoke(params, contextNoToken)).rejects.toThrow('No authentication configured');
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

        itemComment: 'Access revocation required'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('Rate limit exceeded');
    });
  });

  describe('error handler', () => {
    it('should rethrow errors', async () => {
      const testError = new Error('Test error');
      const params = { error: testError };
      const context = {};
      await expect(script.error(params, context)).rejects.toThrow('Test error');
    });

    it('should rethrow errors with status codes', async () => {
      const error = new Error('HTTP 429');
      error.statusCode = 429;
      const params = { error };
      const context = {};
      await expect(script.error(params, context)).rejects.toThrow('HTTP 429');
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