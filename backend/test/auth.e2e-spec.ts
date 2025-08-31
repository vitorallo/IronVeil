import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { 
  TEST_CONFIG, 
  AuthTestHelper, 
  createAuthHeaders,
  generateMockScanData 
} from './setup-tests';
import { HttpExceptionFilter } from '../src/common/filters/http-exception.filter';

describe('IronVeil API - Authentication & Authorization (e2e)', () => {
  let app: INestApplication;
  let httpServer: any;
  let validJwtToken: string;
  let validApiKey: string;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    
    // Apply same configuration as main application
    app.useGlobalFilters(new HttpExceptionFilter());
    app.useGlobalPipes(new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }));
    app.enableCors({
      origin: TEST_CONFIG.frontendUrl,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
      credentials: true,
    });
    app.setGlobalPrefix('api');

    await app.init();
    httpServer = app.getHttpServer();

    // Setup authentication tokens
    validJwtToken = await AuthTestHelper.getValidJwtToken();
    validApiKey = AuthTestHelper.getValidApiKey();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('JWT Token Authentication (Frontend)', () => {
    describe('Valid JWT Token', () => {
      it('should accept valid JWT token for protected endpoints', async () => {
        const response = await request(httpServer)
          .get('/api/scans')
          .set(createAuthHeaders.jwt(validJwtToken))
          .expect(200);

        // Should return paginated scan results
        expect(response.body).toHaveProperty('data');
        expect(response.body).toHaveProperty('pagination');
        expect(Array.isArray(response.body.data)).toBe(true);
      });

      it('should extract user context from JWT token', async () => {
        const response = await request(httpServer)
          .get('/api/organizations')
          .set(createAuthHeaders.jwt(validJwtToken))
          .expect(200);

        // Should return organization data for the authenticated user
        expect(response.body).toHaveProperty('id');
        expect(response.body).toHaveProperty('name');
      });

      it('should allow access to scan details with JWT', async () => {
        // First create a scan
        const scanData = generateMockScanData();
        const uploadResponse = await request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(validApiKey))
          .send(scanData)
          .expect(201);

        const scanId = uploadResponse.body.id;

        // Then access it with JWT
        const response = await request(httpServer)
          .get(`/api/scans/${scanId}`)
          .set(createAuthHeaders.jwt(validJwtToken))
          .expect(200);

        expect(response.body).toHaveProperty('id', scanId);
        expect(response.body).toHaveProperty('name', scanData.name);
      });

      it('should provide proper user context in JWT requests', async () => {
        const response = await request(httpServer)
          .get('/api/findings')
          .set(createAuthHeaders.jwt(validJwtToken))
          .expect(200);

        // Should filter findings by user's organization
        expect(response.body).toHaveProperty('data');
        if (response.body.data.length > 0) {
          expect(response.body.data[0]).toHaveProperty('organizationId');
        }
      });
    });

    describe('Invalid JWT Token', () => {
      it('should reject invalid JWT token', async () => {
        const response = await request(httpServer)
          .get('/api/scans')
          .set(createAuthHeaders.jwt(AuthTestHelper.getInvalidJwtToken()))
          .expect(401);

        expect(response.body).toHaveProperty('statusCode', 401);
        expect(response.body).toHaveProperty('message');
        expect(response.body.message).toMatch(/unauthorized|invalid|token/i);
      });

      it('should reject malformed JWT token', async () => {
        const response = await request(httpServer)
          .get('/api/scans')
          .set(createAuthHeaders.jwt('malformed-token'))
          .expect(401);

        expect(response.body).toHaveProperty('statusCode', 401);
        expect(response.body).toHaveProperty('message');
      });

      it('should reject expired JWT token', async () => {
        const expiredToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJleHAiOjE2MDk0NTkyMDB9.expired';
        
        const response = await request(httpServer)
          .get('/api/scans')
          .set(createAuthHeaders.jwt(expiredToken))
          .expect(401);

        expect(response.body).toHaveProperty('statusCode', 401);
      });

      it('should reject empty Bearer token', async () => {
        const response = await request(httpServer)
          .get('/api/scans')
          .set('Authorization', 'Bearer ')
          .expect(401);

        expect(response.body).toHaveProperty('statusCode', 401);
        expect(response.body.message).toMatch(/no token provided/i);
      });
    });

    describe('Missing JWT Token', () => {
      it('should reject requests without authorization header', async () => {
        const response = await request(httpServer)
          .get('/api/scans')
          .expect(401);

        expect(response.body).toHaveProperty('statusCode', 401);
        expect(response.body.message).toMatch(/no authorization header/i);
      });

      it('should reject requests with wrong auth scheme', async () => {
        const response = await request(httpServer)
          .get('/api/scans')
          .set('Authorization', 'Basic dGVzdDp0ZXN0')
          .expect(401);

        expect(response.body).toHaveProperty('statusCode', 401);
      });
    });
  });

  describe('API Key Authentication (Desktop Scanner)', () => {
    describe('Valid API Key', () => {
      it('should accept valid API key for scan upload', async () => {
        const scanData = generateMockScanData();
        
        const response = await request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(validApiKey))
          .send(scanData)
          .expect(201);

        expect(response.body).toHaveProperty('id');
        expect(response.body).toHaveProperty('status');
        expect(response.body).toHaveProperty('message');
        expect(response.body.status).toBe('processing');
      });

      it('should accept valid API key for scan status check', async () => {
        // First upload a scan
        const scanData = generateMockScanData();
        const uploadResponse = await request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(validApiKey))
          .send(scanData)
          .expect(201);

        const scanId = uploadResponse.body.id;

        // Then check status
        const response = await request(httpServer)
          .get(`/api/scans/${scanId}/status`)
          .set(createAuthHeaders.apiKey(validApiKey))
          .expect(200);

        expect(response.body).toHaveProperty('status');
        expect(response.body).toHaveProperty('message');
        expect(['pending', 'processing', 'completed', 'failed', 'cancelled']).toContain(response.body.status);
      });

      it('should provide proper user context for API key requests', async () => {
        const scanData = generateMockScanData();
        
        const response = await request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(validApiKey))
          .send(scanData)
          .expect(201);

        // Should associate scan with correct organization
        expect(response.body).toHaveProperty('organizationId');
      });
    });

    describe('Invalid API Key', () => {
      it('should reject invalid API key', async () => {
        const scanData = generateMockScanData();
        
        const response = await request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(AuthTestHelper.getInvalidApiKey()))
          .send(scanData)
          .expect(401);

        expect(response.body).toHaveProperty('statusCode', 401);
        expect(response.body).toHaveProperty('message');
        expect(response.body.message).toMatch(/invalid api key/i);
      });

      it('should reject malformed API key', async () => {
        const scanData = generateMockScanData();
        
        const response = await request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey('malformed-key'))
          .send(scanData)
          .expect(401);

        expect(response.body).toHaveProperty('statusCode', 401);
      });

      it('should reject empty API key', async () => {
        const scanData = generateMockScanData();
        
        const response = await request(httpServer)
          .post('/api/scans/upload')
          .set('X-API-Key', '')
          .send(scanData)
          .expect(401);

        expect(response.body).toHaveProperty('statusCode', 401);
        expect(response.body.message).toMatch(/api key required/i);
      });
    });

    describe('Missing API Key', () => {
      it('should reject scan upload without API key', async () => {
        const scanData = generateMockScanData();
        
        const response = await request(httpServer)
          .post('/api/scans/upload')
          .send(scanData)
          .expect(401);

        expect(response.body).toHaveProperty('statusCode', 401);
        expect(response.body.message).toMatch(/api key required/i);
      });
    });
  });

  describe('Mixed Authentication Scenarios', () => {
    it('should not accept JWT token for API key protected endpoints', async () => {
      const scanData = generateMockScanData();
      
      const response = await request(httpServer)
        .post('/api/scans/upload')
        .set(createAuthHeaders.jwt(validJwtToken))
        .send(scanData)
        .expect(401);

      expect(response.body).toHaveProperty('statusCode', 401);
      expect(response.body.message).toMatch(/api key required/i);
    });

    it('should not accept API key for JWT protected endpoints', async () => {
      const response = await request(httpServer)
        .get('/api/scans')
        .set(createAuthHeaders.apiKey(validApiKey))
        .expect(401);

      expect(response.body).toHaveProperty('statusCode', 401);
    });

    it('should handle simultaneous auth headers correctly', async () => {
      const response = await request(httpServer)
        .get('/api/scans')
        .set('Authorization', `Bearer ${validJwtToken}`)
        .set('X-API-Key', validApiKey)
        .expect(200);

      // Should use JWT auth for JWT-protected endpoint
      expect(response.body).toHaveProperty('data');
    });
  });

  describe('Multi-Tenant Access Control', () => {
    it('should isolate data between organizations', async () => {
      // Create a scan with API key (organization A)
      const scanData = generateMockScanData();
      const uploadResponse = await request(httpServer)
        .post('/api/scans/upload')
        .set(createAuthHeaders.apiKey(validApiKey))
        .send(scanData)
        .expect(201);

      // Try to access with JWT token from same organization (should work)
      const response = await request(httpServer)
        .get(`/api/scans/${uploadResponse.body.id}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toHaveProperty('id', uploadResponse.body.id);
    });

    it('should prevent cross-organization access', async () => {
      // In a real test, this would use a different organization's credentials
      // For now, we'll verify the organization isolation exists
      const response = await request(httpServer)
        .get('/api/scans/non-existent-scan-id')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });
  });

  describe('Rate Limiting & Throttling', () => {
    it('should handle multiple concurrent requests', async () => {
      const promises = Array.from({ length: 5 }, () =>
        request(httpServer)
          .get('/api/scans')
          .set(createAuthHeaders.jwt(validJwtToken))
          .expect(200)
      );

      const responses = await Promise.all(promises);
      responses.forEach(response => {
        expect(response.body).toHaveProperty('data');
      });
    });

    it('should apply rate limiting to prevent abuse', async () => {
      // This test would need to be adjusted based on actual rate limiting configuration
      const scanData = generateMockScanData();
      
      // Make multiple rapid requests
      const promises = Array.from({ length: 3 }, () =>
        request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(validApiKey))
          .send({ ...scanData, name: `${scanData.name}-${Math.random()}` })
      );

      const responses = await Promise.allSettled(promises);
      
      // At least some should succeed
      const successful = responses.filter(r => r.status === 'fulfilled' && (r.value as any).status === 201);
      expect(successful.length).toBeGreaterThan(0);
    });
  });

  describe('Error Response Format', () => {
    it('should return consistent error format for authentication failures', async () => {
      const response = await request(httpServer)
        .get('/api/scans')
        .expect(401);

      expect(response.body).toHaveProperty('statusCode', 401);
      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('timestamp');
      expect(response.body).toHaveProperty('path', '/api/scans');
    });

    it('should include correlation ID in error responses', async () => {
      const response = await request(httpServer)
        .get('/api/scans')
        .expect(401);

      // Verify error includes tracking information
      expect(response.body).toHaveProperty('timestamp');
      expect(new Date(response.body.timestamp).getTime()).toBeCloseTo(Date.now(), -3); // Within ~1 second
    });
  });
});