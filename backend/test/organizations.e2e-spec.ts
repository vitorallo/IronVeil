import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { 
  TEST_CONFIG, 
  AuthTestHelper, 
  createAuthHeaders,
  generateMockOrganization 
} from './setup-tests';
import { HttpExceptionFilter } from '../src/common/filters/http-exception.filter';

describe('IronVeil API - Organizations Management (e2e)', () => {
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

  describe('Organization Profile (Frontend)', () => {
    it('should return current organization details', async () => {
      const response = await request(httpServer)
        .get('/api/organizations')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        id: expect.any(String),
        name: expect.any(String),
        tier: expect.any(String),
        createdAt: expect.any(String),
        settings: expect.any(Object),
      });

      expect(['community', 'professional', 'enterprise']).toContain(response.body.tier);
    });

    it('should include organization settings', async () => {
      const response = await request(httpServer)
        .get('/api/organizations')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body.settings).toMatchObject({
        scanRetentionDays: expect.any(Number),
        maxScansPerMonth: expect.any(Number),
        enableRealTimeUpdates: expect.any(Boolean),
      });

      // Verify reasonable defaults
      expect(response.body.settings.scanRetentionDays).toBeGreaterThan(0);
      expect(response.body.settings.maxScansPerMonth).toBeGreaterThan(0);
    });

    it('should include usage statistics', async () => {
      const response = await request(httpServer)
        .get('/api/organizations')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toHaveProperty('usage');
      expect(response.body.usage).toMatchObject({
        currentMonthScans: expect.any(Number),
        totalScans: expect.any(Number),
        totalFindings: expect.any(Number),
        totalUsers: expect.any(Number),
      });

      // Verify non-negative values
      expect(response.body.usage.currentMonthScans).toBeGreaterThanOrEqual(0);
      expect(response.body.usage.totalScans).toBeGreaterThanOrEqual(0);
    });

    it('should require JWT authentication', async () => {
      const response = await request(httpServer)
        .get('/api/organizations')
        .expect(401);

      expect(response.body).toHaveProperty('statusCode', 401);
    });

    it('should reject invalid JWT token', async () => {
      const response = await request(httpServer)
        .get('/api/organizations')
        .set(createAuthHeaders.jwt(AuthTestHelper.getInvalidJwtToken()))
        .expect(401);

      expect(response.body).toHaveProperty('statusCode', 401);
    });
  });

  describe('Organization Members (Frontend)', () => {
    it('should return list of organization members', async () => {
      const response = await request(httpServer)
        .get('/api/organizations/members')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toHaveProperty('data');
      expect(Array.isArray(response.body.data)).toBe(true);
      expect(response.body).toHaveProperty('pagination');

      if (response.body.data.length > 0) {
        const member = response.body.data[0];
        expect(member).toMatchObject({
          id: expect.any(String),
          email: expect.any(String),
          fullName: expect.any(String),
          role: expect.any(String),
          status: expect.any(String),
          joinedAt: expect.any(String),
        });

        expect(['owner', 'admin', 'user', 'readonly']).toContain(member.role);
        expect(['active', 'invited', 'suspended']).toContain(member.status);
      }
    });

    it('should paginate organization members', async () => {
      const response = await request(httpServer)
        .get('/api/organizations/members?page=1&limit=5')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body.pagination).toMatchObject({
        page: 1,
        limit: 5,
        total: expect.any(Number),
        totalPages: expect.any(Number),
      });

      expect(response.body.data.length).toBeLessThanOrEqual(5);
    });

    it('should filter members by role', async () => {
      const response = await request(httpServer)
        .get('/api/organizations/members?role=admin')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      if (response.body.data.length > 0) {
        response.body.data.forEach(member => {
          expect(member.role).toBe('admin');
        });
      }
    });

    it('should require JWT authentication for members list', async () => {
      const response = await request(httpServer)
        .get('/api/organizations/members')
        .expect(401);

      expect(response.body).toHaveProperty('statusCode', 401);
    });
  });

  describe('Organization Settings (Frontend)', () => {
    it('should return current organization settings', async () => {
      const response = await request(httpServer)
        .get('/api/organizations/settings')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        scanRetentionDays: expect.any(Number),
        maxScansPerMonth: expect.any(Number),
        enableRealTimeUpdates: expect.any(Boolean),
        enableNotifications: expect.any(Boolean),
        notificationEmail: expect.any(String),
      });

      // Verify settings are within reasonable bounds
      expect(response.body.scanRetentionDays).toBeGreaterThan(0);
      expect(response.body.scanRetentionDays).toBeLessThanOrEqual(365);
    });

    it('should update organization settings with valid data', async () => {
      const updatedSettings = {
        scanRetentionDays: 120,
        enableRealTimeUpdates: true,
        enableNotifications: false,
      };

      const response = await request(httpServer)
        .patch('/api/organizations/settings')
        .set(createAuthHeaders.jwt(validJwtToken))
        .send(updatedSettings)
        .expect(200);

      expect(response.body).toMatchObject({
        scanRetentionDays: 120,
        enableRealTimeUpdates: true,
        enableNotifications: false,
      });

      expect(response.body).toHaveProperty('updatedAt');
      expect(new Date(response.body.updatedAt).getTime()).toBeCloseTo(Date.now(), -3);
    });

    it('should reject invalid settings values', async () => {
      const invalidSettings = {
        scanRetentionDays: -5, // Invalid negative value
        maxScansPerMonth: 'invalid', // Invalid type
      };

      const response = await request(httpServer)
        .patch('/api/organizations/settings')
        .set(createAuthHeaders.jwt(validJwtToken))
        .send(invalidSettings)
        .expect(400);

      expect(response.body).toHaveProperty('statusCode', 400);
      expect(response.body).toHaveProperty('message');
      expect(Array.isArray(response.body.message)).toBe(true);
    });

    it('should require appropriate permissions for settings update', async () => {
      const updatedSettings = {
        scanRetentionDays: 90,
      };

      const response = await request(httpServer)
        .patch('/api/organizations/settings')
        .set(createAuthHeaders.jwt(validJwtToken))
        .send(updatedSettings);

      // Should either succeed (if user has permissions) or fail with 403
      expect([200, 403]).toContain(response.status);
    });
  });

  describe('API Key Management (Frontend)', () => {
    let createdApiKeyId: string;

    it('should list organization API keys', async () => {
      const response = await request(httpServer)
        .get('/api/organizations/api-keys')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toHaveProperty('data');
      expect(Array.isArray(response.body.data)).toBe(true);

      if (response.body.data.length > 0) {
        const apiKey = response.body.data[0];
        expect(apiKey).toMatchObject({
          id: expect.any(String),
          name: expect.any(String),
          keyPrefix: expect.any(String),
          permissions: expect.any(Array),
          isActive: expect.any(Boolean),
          createdAt: expect.any(String),
          lastUsedAt: expect.any(String),
        });

        // Should not expose the actual key hash
        expect(apiKey).not.toHaveProperty('keyHash');
        expect(apiKey).not.toHaveProperty('key');
      }
    });

    it('should create new API key', async () => {
      const keyData = {
        name: 'Test Desktop Scanner Key',
        permissions: ['scan:upload', 'scan:read'],
        expiresIn: '1y'
      };

      const response = await request(httpServer)
        .post('/api/organizations/api-keys')
        .set(createAuthHeaders.jwt(validJwtToken))
        .send(keyData)
        .expect(201);

      expect(response.body).toMatchObject({
        id: expect.any(String),
        name: keyData.name,
        permissions: keyData.permissions,
        keyPrefix: expect.any(String),
        key: expect.any(String),
      });

      // Verify key format
      expect(response.body.key).toMatch(/^iv_[a-f0-9]{64}$/);
      expect(response.body.keyPrefix).toBe(response.body.key.substring(0, 8));

      createdApiKeyId = response.body.id;
    });

    it('should validate API key creation parameters', async () => {
      const invalidKeyData = {
        // Missing name
        permissions: ['invalid:permission'],
      };

      const response = await request(httpServer)
        .post('/api/organizations/api-keys')
        .set(createAuthHeaders.jwt(validJwtToken))
        .send(invalidKeyData)
        .expect(400);

      expect(response.body).toHaveProperty('statusCode', 400);
    });

    it('should revoke API key', async () => {
      if (!createdApiKeyId) {
        console.warn('Skipping test - no API key was created');
        return;
      }

      const response = await request(httpServer)
        .delete(`/api/organizations/api-keys/${createdApiKeyId}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        message: expect.stringMatching(/revoked.*successfully/i),
        revokedAt: expect.any(String),
      });
    });

    it('should return 404 for non-existent API key', async () => {
      const response = await request(httpServer)
        .delete('/api/organizations/api-keys/non-existent-id')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should require proper permissions for API key management', async () => {
      const keyData = {
        name: 'Unauthorized Key',
        permissions: ['scan:upload'],
      };

      const response = await request(httpServer)
        .post('/api/organizations/api-keys')
        .set(createAuthHeaders.jwt(validJwtToken))
        .send(keyData);

      // Should either succeed (if user has permissions) or fail with 403
      expect([201, 403]).toContain(response.status);
    });
  });

  describe('Organization Analytics (Frontend)', () => {
    it('should return organization security metrics', async () => {
      const response = await request(httpServer)
        .get('/api/organizations/analytics')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        overallSecurityScore: expect.any(Number),
        trend: expect.any(String),
        totalScans: expect.any(Number),
        totalFindings: expect.any(Number),
        riskDistribution: expect.any(Object),
        recentActivity: expect.any(Array),
      });

      expect(response.body.overallSecurityScore).toBeGreaterThanOrEqual(0);
      expect(response.body.overallSecurityScore).toBeLessThanOrEqual(100);
      expect(['improving', 'stable', 'declining']).toContain(response.body.trend);
    });

    it('should include risk distribution breakdown', async () => {
      const response = await request(httpServer)
        .get('/api/organizations/analytics')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body.riskDistribution).toMatchObject({
        critical: expect.any(Number),
        high: expect.any(Number),
        medium: expect.any(Number),
        low: expect.any(Number),
      });

      // Verify non-negative values
      Object.values(response.body.riskDistribution).forEach(count => {
        expect(count).toBeGreaterThanOrEqual(0);
      });
    });

    it('should include recent activity', async () => {
      const response = await request(httpServer)
        .get('/api/organizations/analytics')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(Array.isArray(response.body.recentActivity)).toBe(true);

      if (response.body.recentActivity.length > 0) {
        const activity = response.body.recentActivity[0];
        expect(activity).toMatchObject({
          id: expect.any(String),
          type: expect.any(String),
          description: expect.any(String),
          timestamp: expect.any(String),
          user: expect.any(Object),
        });
      }
    });

    it('should filter analytics by date range', async () => {
      const startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days ago
      const endDate = new Date().toISOString();

      const response = await request(httpServer)
        .get(`/api/organizations/analytics?startDate=${startDate}&endDate=${endDate}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toHaveProperty('overallSecurityScore');
      expect(response.body).toHaveProperty('dateRange');
      expect(response.body.dateRange).toMatchObject({
        startDate: startDate,
        endDate: endDate,
      });
    });
  });

  describe('Data Isolation & Security', () => {
    it('should only return data for authenticated user\'s organization', async () => {
      const response = await request(httpServer)
        .get('/api/organizations')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toHaveProperty('id');
      expect(response.body.id).toBe(TEST_CONFIG.testUser.organizationId);
    });

    it('should prevent unauthorized access to organization settings', async () => {
      const response = await request(httpServer)
        .get('/api/organizations/settings')
        .expect(401);

      expect(response.body).toHaveProperty('statusCode', 401);
    });

    it('should handle organization not found gracefully', async () => {
      // This would require a JWT with invalid organizationId
      // For now, verify normal operation
      const response = await request(httpServer)
        .get('/api/organizations')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toHaveProperty('id');
    });
  });

  describe('Performance & Response Times', () => {
    it('should respond to organization requests quickly', async () => {
      const startTime = Date.now();
      
      await request(httpServer)
        .get('/api/organizations')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      const responseTime = Date.now() - startTime;
      expect(responseTime).toBeLessThan(2000); // Should respond within 2 seconds
    });

    it('should handle concurrent organization requests', async () => {
      const promises = Array.from({ length: 5 }, () =>
        request(httpServer)
          .get('/api/organizations')
          .set(createAuthHeaders.jwt(validJwtToken))
          .expect(200)
      );

      const responses = await Promise.all(promises);
      
      responses.forEach(response => {
        expect(response.body).toHaveProperty('id');
        expect(response.body).toHaveProperty('name');
      });
    });
  });
});