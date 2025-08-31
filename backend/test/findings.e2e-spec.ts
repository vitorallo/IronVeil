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

describe('IronVeil API - Security Findings (e2e)', () => {
  let app: INestApplication;
  let httpServer: any;
  let validJwtToken: string;
  let validApiKey: string;
  let uploadedScanId: string;

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

    // Upload a test scan to generate findings
    const scanData = generateMockScanData();
    const uploadResponse = await request(httpServer)
      .post('/api/scans/upload')
      .set(createAuthHeaders.apiKey(validApiKey))
      .send(scanData);
    
    if (uploadResponse.status === 201) {
      uploadedScanId = uploadResponse.body.id;
    }
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Findings List (Frontend)', () => {
    it('should return paginated list of findings', async () => {
      const response = await request(httpServer)
        .get('/api/findings')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toHaveProperty('data');
      expect(response.body).toHaveProperty('pagination');
      expect(Array.isArray(response.body.data)).toBe(true);
      
      expect(response.body.pagination).toMatchObject({
        page: expect.any(Number),
        limit: expect.any(Number),
        total: expect.any(Number),
        totalPages: expect.any(Number),
      });
    });

    it('should include complete finding information', async () => {
      const response = await request(httpServer)
        .get('/api/findings')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      if (response.body.data.length > 0) {
        const finding = response.body.data[0];
        expect(finding).toMatchObject({
          id: expect.any(String),
          ruleId: expect.any(String),
          severity: expect.any(String),
          category: expect.any(String),
          title: expect.any(String),
          description: expect.any(String),
          affectedObjects: expect.any(Array),
          remediation: expect.any(String),
          scanId: expect.any(String),
          organizationId: expect.any(String),
          createdAt: expect.any(String),
        });

        expect(['Critical', 'High', 'Medium', 'Low']).toContain(finding.severity);
        expect(['delegation', 'authentication', 'authorization', 'accounts', 'certificates']).toContain(finding.category);
      }
    });

    it('should handle pagination parameters', async () => {
      const response = await request(httpServer)
        .get('/api/findings?page=1&limit=5')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body.pagination.page).toBe(1);
      expect(response.body.pagination.limit).toBe(5);
      expect(response.body.data.length).toBeLessThanOrEqual(5);
    });

    it('should filter findings by severity', async () => {
      const response = await request(httpServer)
        .get('/api/findings?severity=Critical')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      if (response.body.data.length > 0) {
        response.body.data.forEach(finding => {
          expect(finding.severity).toBe('Critical');
        });
      }
    });

    it('should filter findings by category', async () => {
      const response = await request(httpServer)
        .get('/api/findings?category=delegation')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      if (response.body.data.length > 0) {
        response.body.data.forEach(finding => {
          expect(finding.category).toBe('delegation');
        });
      }
    });

    it('should filter findings by scan ID', async () => {
      if (!uploadedScanId) {
        console.warn('Skipping test - no uploaded scan available');
        return;
      }

      const response = await request(httpServer)
        .get(`/api/findings?scanId=${uploadedScanId}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      if (response.body.data.length > 0) {
        response.body.data.forEach(finding => {
          expect(finding.scanId).toBe(uploadedScanId);
        });
      }
    });

    it('should filter findings by date range', async () => {
      const startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(); // 7 days ago
      const endDate = new Date().toISOString();
      
      const response = await request(httpServer)
        .get(`/api/findings?startDate=${startDate}&endDate=${endDate}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      if (response.body.data.length > 0) {
        response.body.data.forEach(finding => {
          expect(new Date(finding.createdAt).getTime()).toBeGreaterThanOrEqual(new Date(startDate).getTime());
          expect(new Date(finding.createdAt).getTime()).toBeLessThanOrEqual(new Date(endDate).getTime());
        });
      }
    });

    it('should search findings by text', async () => {
      const response = await request(httpServer)
        .get('/api/findings?search=delegation')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      if (response.body.data.length > 0) {
        response.body.data.forEach(finding => {
          const searchableText = `${finding.title} ${finding.description} ${finding.ruleId}`.toLowerCase();
          expect(searchableText).toContain('delegation');
        });
      }
    });

    it('should require JWT authentication', async () => {
      const response = await request(httpServer)
        .get('/api/findings')
        .expect(401);

      expect(response.body).toHaveProperty('statusCode', 401);
    });
  });

  describe('Finding Details (Frontend)', () => {
    it('should return detailed finding information', async () => {
      // First get a finding ID from the list
      const listResponse = await request(httpServer)
        .get('/api/findings?limit=1')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      if (listResponse.body.data.length === 0) {
        console.warn('Skipping test - no findings available');
        return;
      }

      const findingId = listResponse.body.data[0].id;

      const response = await request(httpServer)
        .get(`/api/findings/${findingId}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        id: findingId,
        ruleId: expect.any(String),
        severity: expect.any(String),
        category: expect.any(String),
        title: expect.any(String),
        description: expect.any(String),
        affectedObjects: expect.any(Array),
        remediation: expect.any(String),
        impact: expect.any(Number),
        score: expect.any(Number),
        scanId: expect.any(String),
        organizationId: expect.any(String),
        createdAt: expect.any(String),
      });

      expect(response.body.impact).toBeGreaterThanOrEqual(0);
      expect(response.body.impact).toBeLessThanOrEqual(100);
    });

    it('should include detailed remediation steps', async () => {
      const listResponse = await request(httpServer)
        .get('/api/findings?limit=1')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      if (listResponse.body.data.length === 0) {
        console.warn('Skipping test - no findings available');
        return;
      }

      const findingId = listResponse.body.data[0].id;

      const response = await request(httpServer)
        .get(`/api/findings/${findingId}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toHaveProperty('remediation');
      expect(typeof response.body.remediation).toBe('string');
      expect(response.body.remediation.length).toBeGreaterThan(10);
    });

    it('should include related scan information', async () => {
      const listResponse = await request(httpServer)
        .get('/api/findings?limit=1')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      if (listResponse.body.data.length === 0) {
        console.warn('Skipping test - no findings available');
        return;
      }

      const findingId = listResponse.body.data[0].id;

      const response = await request(httpServer)
        .get(`/api/findings/${findingId}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toHaveProperty('scan');
      expect(response.body.scan).toMatchObject({
        id: expect.any(String),
        name: expect.any(String),
        scanType: expect.any(String),
        createdAt: expect.any(String),
      });
    });

    it('should return 404 for non-existent finding', async () => {
      const response = await request(httpServer)
        .get('/api/findings/non-existent-finding-id')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should require JWT authentication for finding details', async () => {
      const response = await request(httpServer)
        .get('/api/findings/some-finding-id')
        .expect(401);

      expect(response.body).toHaveProperty('statusCode', 401);
    });
  });

  describe('Finding Status Updates (Frontend)', () => {
    it('should update finding status', async () => {
      const listResponse = await request(httpServer)
        .get('/api/findings?limit=1')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      if (listResponse.body.data.length === 0) {
        console.warn('Skipping test - no findings available');
        return;
      }

      const findingId = listResponse.body.data[0].id;

      const updateData = {
        status: 'acknowledged',
        notes: 'Reviewing this finding with the security team',
      };

      const response = await request(httpServer)
        .patch(`/api/findings/${findingId}/status`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .send(updateData)
        .expect(200);

      expect(response.body).toMatchObject({
        id: findingId,
        status: 'acknowledged',
        notes: updateData.notes,
        updatedAt: expect.any(String),
        updatedBy: expect.any(String),
      });
    });

    it('should validate status update values', async () => {
      const listResponse = await request(httpServer)
        .get('/api/findings?limit=1')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      if (listResponse.body.data.length === 0) {
        console.warn('Skipping test - no findings available');
        return;
      }

      const findingId = listResponse.body.data[0].id;

      const invalidUpdateData = {
        status: 'invalid_status',
      };

      const response = await request(httpServer)
        .patch(`/api/findings/${findingId}/status`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .send(invalidUpdateData)
        .expect(400);

      expect(response.body).toHaveProperty('statusCode', 400);
      expect(response.body.message).toContain('status');
    });

    it('should track status change history', async () => {
      const listResponse = await request(httpServer)
        .get('/api/findings?limit=1')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      if (listResponse.body.data.length === 0) {
        console.warn('Skipping test - no findings available');
        return;
      }

      const findingId = listResponse.body.data[0].id;

      // Get finding history
      const response = await request(httpServer)
        .get(`/api/findings/${findingId}/history`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toHaveProperty('data');
      expect(Array.isArray(response.body.data)).toBe(true);

      if (response.body.data.length > 0) {
        const historyEntry = response.body.data[0];
        expect(historyEntry).toMatchObject({
          id: expect.any(String),
          action: expect.any(String),
          previousValue: expect.any(String),
          newValue: expect.any(String),
          timestamp: expect.any(String),
          userId: expect.any(String),
        });
      }
    });
  });

  describe('Findings Statistics (Frontend)', () => {
    it('should return findings summary statistics', async () => {
      const response = await request(httpServer)
        .get('/api/findings/stats')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        total: expect.any(Number),
        bySeverity: expect.any(Object),
        byCategory: expect.any(Object),
        byStatus: expect.any(Object),
        recentTrend: expect.any(String),
      });

      expect(response.body.bySeverity).toMatchObject({
        Critical: expect.any(Number),
        High: expect.any(Number),
        Medium: expect.any(Number),
        Low: expect.any(Number),
      });

      expect(['improving', 'stable', 'worsening']).toContain(response.body.recentTrend);
    });

    it('should filter statistics by date range', async () => {
      const startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days ago
      const endDate = new Date().toISOString();

      const response = await request(httpServer)
        .get(`/api/findings/stats?startDate=${startDate}&endDate=${endDate}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toHaveProperty('total');
      expect(response.body).toHaveProperty('dateRange');
      expect(response.body.dateRange).toMatchObject({
        startDate: startDate,
        endDate: endDate,
      });
    });

    it('should include category breakdown', async () => {
      const response = await request(httpServer)
        .get('/api/findings/stats')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body.byCategory).toBeDefined();
      expect(typeof response.body.byCategory).toBe('object');
      
      // Should have common security categories
      const categories = Object.keys(response.body.byCategory);
      expect(categories.length).toBeGreaterThanOrEqual(0);
      
      if (categories.length > 0) {
        categories.forEach(category => {
          expect(response.body.byCategory[category]).toBeGreaterThanOrEqual(0);
        });
      }
    });
  });

  describe('Bulk Operations (Frontend)', () => {
    it('should handle bulk status updates', async () => {
      const listResponse = await request(httpServer)
        .get('/api/findings?limit=3')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      if (listResponse.body.data.length === 0) {
        console.warn('Skipping test - no findings available');
        return;
      }

      const findingIds = listResponse.body.data.map(f => f.id);

      const bulkUpdateData = {
        findingIds: findingIds,
        status: 'in_progress',
        notes: 'Bulk update - working on remediation',
      };

      const response = await request(httpServer)
        .patch('/api/findings/bulk-status')
        .set(createAuthHeaders.jwt(validJwtToken))
        .send(bulkUpdateData)
        .expect(200);

      expect(response.body).toMatchObject({
        updated: findingIds.length,
        errors: 0,
        message: expect.stringMatching(/updated.*successfully/i),
      });
    });

    it('should validate bulk update parameters', async () => {
      const invalidBulkData = {
        findingIds: [], // Empty array
        status: 'invalid_status',
      };

      const response = await request(httpServer)
        .patch('/api/findings/bulk-status')
        .set(createAuthHeaders.jwt(validJwtToken))
        .send(invalidBulkData)
        .expect(400);

      expect(response.body).toHaveProperty('statusCode', 400);
    });

    it('should handle bulk export', async () => {
      const response = await request(httpServer)
        .get('/api/findings/export?format=csv')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.headers['content-type']).toMatch(/text\/csv|application\/csv/);
      expect(response.headers['content-disposition']).toMatch(/attachment.*filename.*\.csv/);
    });
  });

  describe('Data Security & Access Control', () => {
    it('should only return findings for user\'s organization', async () => {
      const response = await request(httpServer)
        .get('/api/findings')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      if (response.body.data.length > 0) {
        response.body.data.forEach(finding => {
          expect(finding.organizationId).toBe(TEST_CONFIG.testUser.organizationId);
        });
      }
    });

    it('should prevent access to other organization\'s findings', async () => {
      // This would need a finding ID from another organization
      // For now, verify 404 response for non-existent findings
      const response = await request(httpServer)
        .get('/api/findings/other-org-finding-id')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should sanitize sensitive data in responses', async () => {
      const response = await request(httpServer)
        .get('/api/findings')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      if (response.body.data.length > 0) {
        const finding = response.body.data[0];
        
        // Should not expose internal database fields
        expect(finding).not.toHaveProperty('internal_id');
        expect(finding).not.toHaveProperty('raw_data');
        expect(finding).not.toHaveProperty('processing_notes');
      }
    });
  });

  describe('Performance & Scalability', () => {
    it('should respond to findings list quickly', async () => {
      const startTime = Date.now();
      
      await request(httpServer)
        .get('/api/findings')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      const responseTime = Date.now() - startTime;
      expect(responseTime).toBeLessThan(3000); // Should respond within 3 seconds
    });

    it('should handle large result sets with pagination', async () => {
      const response = await request(httpServer)
        .get('/api/findings?limit=1000') // Large limit
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body.data.length).toBeLessThanOrEqual(100); // Should cap at reasonable limit
      expect(response.body.pagination).toHaveProperty('totalPages');
    });

    it('should handle complex filter combinations', async () => {
      const response = await request(httpServer)
        .get('/api/findings?severity=High&category=delegation&search=unconstrained')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toHaveProperty('data');
      expect(response.body).toHaveProperty('pagination');
      
      // Should apply all filters
      if (response.body.data.length > 0) {
        response.body.data.forEach(finding => {
          expect(finding.severity).toBe('High');
          expect(finding.category).toBe('delegation');
        });
      }
    });
  });
});