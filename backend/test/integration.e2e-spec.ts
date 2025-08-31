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

describe('IronVeil API - Integration & End-to-End Workflows (e2e)', () => {
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

  describe('Complete Desktop Scanner Workflow', () => {
    it('should handle full desktop scanner to dashboard workflow', async () => {
      // Step 1: Desktop scanner uploads scan results
      const scanData = generateMockScanData();
      const uploadResponse = await request(httpServer)
        .post('/api/scans/upload')
        .set(createAuthHeaders.apiKey(validApiKey))
        .send(scanData)
        .expect(201);

      expect(uploadResponse.body).toMatchObject({
        id: expect.any(String),
        name: scanData.name,
        status: 'processing',
        message: expect.stringMatching(/uploaded.*successfully/i),
      });

      const scanId = uploadResponse.body.id;

      // Step 2: Desktop scanner checks processing status
      const statusResponse = await request(httpServer)
        .get(`/api/scans/${scanId}/status`)
        .set(createAuthHeaders.apiKey(validApiKey))
        .expect(200);

      expect(statusResponse.body).toMatchObject({
        status: expect.any(String),
        message: expect.any(String),
      });

      // Step 3: Frontend dashboard retrieves updated scan list
      const scansListResponse = await request(httpServer)
        .get('/api/scans')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(scansListResponse.body.data).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            id: scanId,
            name: scanData.name,
          })
        ])
      );

      // Step 4: Frontend retrieves detailed scan results
      const scanDetailsResponse = await request(httpServer)
        .get(`/api/scans/${scanId}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(scanDetailsResponse.body).toMatchObject({
        id: scanId,
        name: scanData.name,
        totalFindings: scanData.scanData.findings.length,
        overallScore: expect.any(Number),
      });

      // Step 5: Frontend retrieves scan findings
      const findingsResponse = await request(httpServer)
        .get(`/api/findings?scanId=${scanId}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(findingsResponse.body.data.length).toBeGreaterThan(0);
      expect(findingsResponse.body.data[0]).toMatchObject({
        scanId: scanId,
        ruleId: expect.any(String),
        severity: expect.any(String),
      });

      // Step 6: Dashboard updates analytics
      const analyticsResponse = await request(httpServer)
        .get('/api/analytics/dashboard')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(analyticsResponse.body).toMatchObject({
        totalScans: expect.any(Number),
        totalFindings: expect.any(Number),
        overallSecurityScore: expect.any(Number),
      });

      // Verify the new scan is reflected in analytics
      expect(analyticsResponse.body.totalScans).toBeGreaterThan(0);
      expect(analyticsResponse.body.totalFindings).toBeGreaterThan(0);
    });

    it('should maintain data consistency across all endpoints', async () => {
      const scanData = generateMockScanData();
      
      // Upload scan
      const uploadResponse = await request(httpServer)
        .post('/api/scans/upload')
        .set(createAuthHeaders.apiKey(validApiKey))
        .send(scanData)
        .expect(201);

      const scanId = uploadResponse.body.id;

      // Get scan details
      const scanDetails = await request(httpServer)
        .get(`/api/scans/${scanId}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      // Get findings for this scan
      const findings = await request(httpServer)
        .get(`/api/findings?scanId=${scanId}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      // Get organization analytics
      const analytics = await request(httpServer)
        .get('/api/analytics/dashboard')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      // Verify data consistency
      expect(scanDetails.body.totalFindings).toBe(findings.body.data.length);
      expect(scanDetails.body.totalFindings).toBe(scanData.scanData.findings.length);
      
      // Verify findings severity breakdown matches
      const criticalCount = findings.body.data.filter(f => f.severity === 'Critical').length;
      const expectedCritical = scanData.scanData.findings.filter(f => f.severity === 'Critical').length;
      expect(criticalCount).toBe(expectedCritical);
    });
  });

  describe('Multi-User Organization Workflow', () => {
    it('should handle concurrent user access to shared organization data', async () => {
      // Simulate multiple users from same organization accessing data concurrently
      const promises = [
        // User 1: Gets dashboard
        request(httpServer)
          .get('/api/analytics/dashboard')
          .set(createAuthHeaders.jwt(validJwtToken))
          .expect(200),
        
        // User 2: Gets scans list
        request(httpServer)
          .get('/api/scans')
          .set(createAuthHeaders.jwt(validJwtToken))
          .expect(200),
        
        // User 3: Gets findings
        request(httpServer)
          .get('/api/findings')
          .set(createAuthHeaders.jwt(validJwtToken))
          .expect(200),
        
        // User 4: Gets organization info
        request(httpServer)
          .get('/api/organizations')
          .set(createAuthHeaders.jwt(validJwtToken))
          .expect(200),
      ];

      const responses = await Promise.all(promises);
      
      // All requests should succeed
      responses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body).toBeDefined();
      });

      // Verify consistent organization context
      const orgResponse = responses[3]; // Organization response
      const organizationId = orgResponse.body.id;

      // Other responses should be scoped to same organization
      const dashboardResponse = responses[0];
      const scansResponse = responses[1];
      
      if (scansResponse.body.data.length > 0) {
        expect(scansResponse.body.data[0].organizationId).toBe(organizationId);
      }
    });

    it('should handle organization settings updates affecting multiple users', async () => {
      // User 1: Updates organization settings
      const settingsUpdate = {
        scanRetentionDays: 180,
        enableRealTimeUpdates: true,
      };

      const updateResponse = await request(httpServer)
        .patch('/api/organizations/settings')
        .set(createAuthHeaders.jwt(validJwtToken))
        .send(settingsUpdate)
        .expect(200);

      expect(updateResponse.body.scanRetentionDays).toBe(180);

      // User 2: Retrieves updated organization info
      const orgResponse = await request(httpServer)
        .get('/api/organizations')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(orgResponse.body.settings.scanRetentionDays).toBe(180);
      expect(orgResponse.body.settings.enableRealTimeUpdates).toBe(true);

      // User 3: Settings should be reflected in dashboard
      const dashboardResponse = await request(httpServer)
        .get('/api/analytics/dashboard')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(dashboardResponse.body).toBeDefined(); // Settings affect dashboard behavior
    });
  });

  describe('Error Handling & Recovery Workflows', () => {
    it('should handle scan upload failures gracefully', async () => {
      // Upload malformed scan data
      const malformedScan = {
        name: 'Invalid Scan',
        scanType: 'invalid_type', // Invalid scan type
        scanData: 'not-an-object', // Invalid scan data
      };

      const uploadResponse = await request(httpServer)
        .post('/api/scans/upload')
        .set(createAuthHeaders.apiKey(validApiKey))
        .send(malformedScan)
        .expect(400);

      expect(uploadResponse.body).toMatchObject({
        statusCode: 400,
        message: expect.any(Array),
        timestamp: expect.any(String),
        path: '/api/scans/upload',
      });

      // Frontend should still be able to retrieve existing data
      const scansResponse = await request(httpServer)
        .get('/api/scans')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(scansResponse.body).toHaveProperty('data');
      expect(scansResponse.body).toHaveProperty('pagination');
    });

    it('should handle authentication token expiration workflow', async () => {
      // Try with invalid token
      const invalidToken = 'expired-or-invalid-token';
      
      const response = await request(httpServer)
        .get('/api/scans')
        .set(createAuthHeaders.jwt(invalidToken))
        .expect(401);

      expect(response.body).toMatchObject({
        statusCode: 401,
        message: expect.stringMatching(/unauthorized|invalid|token/i),
      });

      // Frontend should be able to re-authenticate and succeed
      const validResponse = await request(httpServer)
        .get('/api/scans')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(validResponse.body).toHaveProperty('data');
    });

    it('should handle rate limiting and backoff', async () => {
      // Make rapid requests to test rate limiting
      const rapidRequests = Array.from({ length: 10 }, (_, i) =>
        request(httpServer)
          .get('/api/scans')
          .set(createAuthHeaders.jwt(validJwtToken))
      );

      const responses = await Promise.allSettled(rapidRequests);
      
      // Some should succeed, some might be rate limited
      const successful = responses.filter(r => r.status === 'fulfilled' && (r.value as any).status === 200);
      const rateLimited = responses.filter(r => r.status === 'fulfilled' && (r.value as any).status === 429);

      // At least some should succeed
      expect(successful.length).toBeGreaterThan(0);
      
      // If rate limiting is implemented, verify proper response
      if (rateLimited.length > 0) {
        const limitedResponse = rateLimited[0] as any;
        expect(limitedResponse.value.status).toBe(429);
      }
    });
  });

  describe('Real-time Updates & WebSocket Simulation', () => {
    it('should support real-time dashboard updates after scan completion', async () => {
      // Get initial dashboard state
      const initialDashboard = await request(httpServer)
        .get('/api/analytics/dashboard')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      const initialScansCount = initialDashboard.body.totalScans;
      const initialFindingsCount = initialDashboard.body.totalFindings;

      // Upload new scan
      const scanData = generateMockScanData();
      await request(httpServer)
        .post('/api/scans/upload')
        .set(createAuthHeaders.apiKey(validApiKey))
        .send(scanData)
        .expect(201);

      // Get updated dashboard state
      const updatedDashboard = await request(httpServer)
        .get('/api/analytics/dashboard')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      // Verify dashboard reflects new scan
      expect(updatedDashboard.body.totalScans).toBeGreaterThan(initialScansCount);
      expect(updatedDashboard.body.totalFindings).toBeGreaterThan(initialFindingsCount);

      // Verify findings increase matches uploaded findings
      const findingsDelta = updatedDashboard.body.totalFindings - initialFindingsCount;
      expect(findingsDelta).toBe(scanData.scanData.findings.length);
    });

    it('should maintain real-time activity feed', async () => {
      // Get initial activity
      const initialActivity = await request(httpServer)
        .get('/api/analytics/dashboard')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      const initialActivityCount = initialActivity.body.recentActivity.length;

      // Perform action that should generate activity
      const scanData = generateMockScanData();
      const uploadResponse = await request(httpServer)
        .post('/api/scans/upload')
        .set(createAuthHeaders.apiKey(validApiKey))
        .send(scanData)
        .expect(201);

      // Get updated activity
      const updatedActivity = await request(httpServer)
        .get('/api/analytics/dashboard')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      // Should have new activity entry
      expect(updatedActivity.body.recentActivity.length).toBeGreaterThanOrEqual(initialActivityCount);

      // Most recent activity should be related to the scan upload
      const mostRecentActivity = updatedActivity.body.recentActivity[0];
      expect(mostRecentActivity).toMatchObject({
        type: expect.any(String),
        title: expect.any(String),
        timestamp: expect.any(String),
      });
    });
  });

  describe('API Performance Under Load', () => {
    it('should handle concurrent scan uploads', async () => {
      const concurrentScans = Array.from({ length: 3 }, (_, i) => {
        const scanData = {
          ...generateMockScanData(),
          name: `Concurrent Scan ${i + 1}`,
        };
        
        return request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(validApiKey))
          .send(scanData);
      });

      const responses = await Promise.all(concurrentScans);
      
      // All uploads should succeed
      responses.forEach((response, i) => {
        expect(response.status).toBe(201);
        expect(response.body.name).toBe(`Concurrent Scan ${i + 1}`);
      });

      // Dashboard should reflect all new scans
      const dashboardResponse = await request(httpServer)
        .get('/api/analytics/dashboard')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(dashboardResponse.body.totalScans).toBeGreaterThan(0);
    });

    it('should handle mixed API and frontend requests concurrently', async () => {
      const mixedRequests = [
        // API key requests (desktop scanner simulation)
        request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(validApiKey))
          .send(generateMockScanData()),
        
        // JWT requests (frontend simulation)
        request(httpServer)
          .get('/api/scans')
          .set(createAuthHeaders.jwt(validJwtToken)),
        
        request(httpServer)
          .get('/api/findings')
          .set(createAuthHeaders.jwt(validJwtToken)),
        
        request(httpServer)
          .get('/api/analytics/dashboard')
          .set(createAuthHeaders.jwt(validJwtToken)),
      ];

      const responses = await Promise.all(mixedRequests);
      
      // First request should be 201 (scan upload)
      expect(responses[0].status).toBe(201);
      
      // Remaining requests should be 200
      for (let i = 1; i < responses.length; i++) {
        expect(responses[i].status).toBe(200);
      }
    });

    it('should maintain response times under concurrent load', async () => {
      const startTime = Date.now();
      
      const loadRequests = Array.from({ length: 5 }, () =>
        request(httpServer)
          .get('/api/analytics/dashboard')
          .set(createAuthHeaders.jwt(validJwtToken))
          .expect(200)
      );

      await Promise.all(loadRequests);
      
      const totalTime = Date.now() - startTime;
      const averageTime = totalTime / 5;
      
      // Average response time should be reasonable
      expect(averageTime).toBeLessThan(2000); // Less than 2 seconds average
    });
  });

  describe('Cross-Service Data Integrity', () => {
    it('should maintain referential integrity across all endpoints', async () => {
      // Upload scan
      const scanData = generateMockScanData();
      const uploadResponse = await request(httpServer)
        .post('/api/scans/upload')
        .set(createAuthHeaders.apiKey(validApiKey))
        .send(scanData)
        .expect(201);

      const scanId = uploadResponse.body.id;

      // Get scan from scans endpoint
      const scanFromScansEndpoint = await request(httpServer)
        .get(`/api/scans/${scanId}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      // Get findings from findings endpoint
      const findingsResponse = await request(httpServer)
        .get(`/api/findings?scanId=${scanId}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      // Get scan results
      const resultsResponse = await request(httpServer)
        .get(`/api/scans/${scanId}/results`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      // Verify all endpoints return consistent data
      expect(scanFromScansEndpoint.body.id).toBe(scanId);
      expect(resultsResponse.body.scanId).toBe(scanId);
      
      if (findingsResponse.body.data.length > 0) {
        findingsResponse.body.data.forEach(finding => {
          expect(finding.scanId).toBe(scanId);
        });
      }

      // Verify counts match
      expect(scanFromScansEndpoint.body.totalFindings).toBe(findingsResponse.body.data.length);
      expect(resultsResponse.body.findings.length).toBe(findingsResponse.body.data.length);
    });

    it('should maintain organization isolation across all endpoints', async () => {
      // Get data from multiple endpoints
      const endpoints = [
        '/api/scans',
        '/api/findings',
        '/api/organizations',
        '/api/analytics/dashboard',
      ];

      for (const endpoint of endpoints) {
        const response = await request(httpServer)
          .get(endpoint)
          .set(createAuthHeaders.jwt(validJwtToken))
          .expect(200);

        // Verify organization context is consistent
        if (response.body.data && Array.isArray(response.body.data)) {
          response.body.data.forEach(item => {
            if (item.organizationId) {
              expect(item.organizationId).toBe(TEST_CONFIG.testUser.organizationId);
            }
          });
        }

        if (response.body.id) {
          expect(response.body.id).toBe(TEST_CONFIG.testUser.organizationId);
        }
      }
    });
  });

  describe('System Health & Monitoring', () => {
    it('should provide system health information', async () => {
      const response = await request(httpServer)
        .get('/api')
        .expect(200);

      expect(response.body).toMatchObject({
        status: 'healthy',
        version: '1.0.0',
        timestamp: expect.any(String),
      });

      // Verify timestamp is recent
      const timestamp = new Date(response.body.timestamp);
      const now = new Date();
      const timeDiff = now.getTime() - timestamp.getTime();
      expect(timeDiff).toBeLessThan(5000); // Within 5 seconds
    });

    it('should handle service availability checks', async () => {
      // Check all major endpoints are available
      const healthChecks = [
        request(httpServer).get('/api').expect(200),
        request(httpServer).get('/api/docs').expect(200),
      ];

      const responses = await Promise.all(healthChecks);
      
      responses.forEach(response => {
        expect(response.status).toBe(200);
      });
    });
  });
});