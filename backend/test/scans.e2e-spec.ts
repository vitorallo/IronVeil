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

describe('IronVeil API - Scans Management (e2e)', () => {
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

    // Upload a test scan that we can use throughout the tests
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

  describe('Scan Upload (Desktop Scanner)', () => {
    describe('Valid Scan Upload', () => {
      it('should accept valid scan data from desktop scanner', async () => {
        const scanData = generateMockScanData();
        
        const response = await request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(validApiKey))
          .send(scanData)
          .expect(201);

        expect(response.body).toMatchObject({
          id: expect.any(String),
          name: scanData.name,
          scanType: scanData.scanType,
          status: 'processing',
          createdAt: expect.any(String),
          organizationId: expect.any(String),
        });

        expect(response.body).toHaveProperty('message');
        expect(response.body.message).toMatch(/uploaded.*successfully/i);
      });

      it('should handle hybrid scan type correctly', async () => {
        const scanData = {
          ...generateMockScanData(),
          scanType: 'hybrid'
        };
        
        const response = await request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(validApiKey))
          .send(scanData)
          .expect(201);

        expect(response.body.scanType).toBe('hybrid');
      });

      it('should handle AD-only scan type correctly', async () => {
        const scanData = {
          ...generateMockScanData(),
          scanType: 'ad_only'
        };
        
        const response = await request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(validApiKey))
          .send(scanData)
          .expect(201);

        expect(response.body.scanType).toBe('ad_only');
      });

      it('should process scan findings correctly', async () => {
        const scanData = generateMockScanData();
        
        const response = await request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(validApiKey))
          .send(scanData)
          .expect(201);

        expect(response.body).toHaveProperty('totalFindings');
        expect(response.body).toHaveProperty('criticalCount');
        expect(response.body).toHaveProperty('highCount');
        expect(response.body).toHaveProperty('mediumCount');
        expect(response.body).toHaveProperty('lowCount');
        expect(response.body).toHaveProperty('overallScore');
      });

      it('should return proper response time for scan upload', async () => {
        const scanData = generateMockScanData();
        const startTime = Date.now();
        
        await request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(validApiKey))
          .send(scanData)
          .expect(201);

        const responseTime = Date.now() - startTime;
        expect(responseTime).toBeLessThan(5000); // Should process within 5 seconds
      });
    });

    describe('Invalid Scan Upload', () => {
      it('should reject scan with missing required fields', async () => {
        const invalidScanData = {
          // Missing name and scanData
          scanType: 'hybrid'
        };
        
        const response = await request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(validApiKey))
          .send(invalidScanData)
          .expect(400);

        expect(response.body).toHaveProperty('statusCode', 400);
        expect(response.body).toHaveProperty('message');
        expect(Array.isArray(response.body.message)).toBe(true);
      });

      it('should reject scan with invalid scan type', async () => {
        const scanData = {
          ...generateMockScanData(),
          scanType: 'invalid_type'
        };
        
        const response = await request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(validApiKey))
          .send(scanData)
          .expect(400);

        expect(response.body).toHaveProperty('statusCode', 400);
        expect(response.body.message).toContain('scanType');
      });

      it('should reject scan with malformed findings data', async () => {
        const scanData = generateMockScanData();
        scanData.scanData.findings = 'invalid-findings-format';
        
        const response = await request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(validApiKey))
          .send(scanData)
          .expect(400);

        expect(response.body).toHaveProperty('statusCode', 400);
      });

      it('should reject extremely large scan payloads', async () => {
        const scanData = generateMockScanData();
        // Create very large findings array
        scanData.scanData.findings = Array.from({ length: 10000 }, (_, i) => ({
          ruleId: `RULE-${i}`,
          severity: 'Low',
          category: 'test',
          description: `Finding ${i}`.repeat(1000), // Very long description
          affectedObjects: [`Object${i}`],
          score: 10,
          impact: 5,
          remediation: 'Test remediation'
        }));
        
        const response = await request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(validApiKey))
          .send(scanData);

        // Should either accept it (if within limits) or reject with proper error
        expect([201, 413, 400]).toContain(response.status);
      });
    });
  });

  describe('Scan Status Check (Desktop Scanner)', () => {
    it('should return scan status for valid scan ID', async () => {
      if (!uploadedScanId) {
        console.warn('Skipping test - no uploaded scan available');
        return;
      }

      const response = await request(httpServer)
        .get(`/api/scans/${uploadedScanId}/status`)
        .set(createAuthHeaders.apiKey(validApiKey))
        .expect(200);

      expect(response.body).toHaveProperty('status');
      expect(response.body).toHaveProperty('message');
      expect(['pending', 'processing', 'completed', 'failed', 'cancelled']).toContain(response.body.status);
    });

    it('should return 404 for non-existent scan ID', async () => {
      const response = await request(httpServer)
        .get('/api/scans/non-existent-scan-id/status')
        .set(createAuthHeaders.apiKey(validApiKey))
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should reject status check without API key', async () => {
      if (!uploadedScanId) {
        console.warn('Skipping test - no uploaded scan available');
        return;
      }

      const response = await request(httpServer)
        .get(`/api/scans/${uploadedScanId}/status`)
        .expect(401);

      expect(response.body).toHaveProperty('statusCode', 401);
      expect(response.body.message).toMatch(/api key required/i);
    });
  });

  describe('Scan Listing (Frontend)', () => {
    it('should return paginated list of scans', async () => {
      const response = await request(httpServer)
        .get('/api/scans')
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

    it('should handle pagination parameters', async () => {
      const response = await request(httpServer)
        .get('/api/scans?page=1&limit=5')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body.pagination.page).toBe(1);
      expect(response.body.pagination.limit).toBe(5);
      expect(response.body.data.length).toBeLessThanOrEqual(5);
    });

    it('should filter scans by scan type', async () => {
      const response = await request(httpServer)
        .get('/api/scans?scanType=hybrid')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toHaveProperty('data');
      
      // If there are results, they should all be hybrid type
      if (response.body.data.length > 0) {
        response.body.data.forEach(scan => {
          expect(scan.scanType).toBe('hybrid');
        });
      }
    });

    it('should filter scans by status', async () => {
      const response = await request(httpServer)
        .get('/api/scans?status=completed')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toHaveProperty('data');
      
      // If there are results, they should all be completed
      if (response.body.data.length > 0) {
        response.body.data.forEach(scan => {
          expect(scan.status).toBe('completed');
        });
      }
    });

    it('should filter scans by date range', async () => {
      const startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(); // 7 days ago
      const endDate = new Date().toISOString();
      
      const response = await request(httpServer)
        .get(`/api/scans?startDate=${startDate}&endDate=${endDate}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toHaveProperty('data');
      
      // Verify dates are within range
      if (response.body.data.length > 0) {
        response.body.data.forEach(scan => {
          expect(new Date(scan.createdAt).getTime()).toBeGreaterThanOrEqual(new Date(startDate).getTime());
          expect(new Date(scan.createdAt).getTime()).toBeLessThanOrEqual(new Date(endDate).getTime());
        });
      }
    });

    it('should handle invalid query parameters gracefully', async () => {
      const response = await request(httpServer)
        .get('/api/scans?page=invalid&limit=xyz')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(400);

      expect(response.body).toHaveProperty('statusCode', 400);
    });
  });

  describe('Scan Details (Frontend)', () => {
    it('should return detailed scan information', async () => {
      if (!uploadedScanId) {
        console.warn('Skipping test - no uploaded scan available');
        return;
      }

      const response = await request(httpServer)
        .get(`/api/scans/${uploadedScanId}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        id: uploadedScanId,
        name: expect.any(String),
        scanType: expect.any(String),
        status: expect.any(String),
        createdAt: expect.any(String),
        organizationId: expect.any(String),
      });

      expect(response.body).toHaveProperty('totalFindings');
      expect(response.body).toHaveProperty('overallScore');
    });

    it('should return 404 for non-existent scan', async () => {
      const response = await request(httpServer)
        .get('/api/scans/non-existent-scan-id')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should require JWT authentication', async () => {
      if (!uploadedScanId) {
        console.warn('Skipping test - no uploaded scan available');
        return;
      }

      const response = await request(httpServer)
        .get(`/api/scans/${uploadedScanId}`)
        .expect(401);

      expect(response.body).toHaveProperty('statusCode', 401);
    });
  });

  describe('Scan Results (Frontend)', () => {
    it('should return detailed scan results with findings', async () => {
      if (!uploadedScanId) {
        console.warn('Skipping test - no uploaded scan available');
        return;
      }

      const response = await request(httpServer)
        .get(`/api/scans/${uploadedScanId}/results`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toHaveProperty('scanId', uploadedScanId);
      expect(response.body).toHaveProperty('findings');
      expect(response.body).toHaveProperty('summary');
      expect(Array.isArray(response.body.findings)).toBe(true);
    });

    it('should include finding details', async () => {
      if (!uploadedScanId) {
        console.warn('Skipping test - no uploaded scan available');
        return;
      }

      const response = await request(httpServer)
        .get(`/api/scans/${uploadedScanId}/results`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      if (response.body.findings.length > 0) {
        const finding = response.body.findings[0];
        expect(finding).toMatchObject({
          ruleId: expect.any(String),
          severity: expect.any(String),
          category: expect.any(String),
          description: expect.any(String),
          affectedObjects: expect.any(Array),
        });
      }
    });

    it('should return 404 for non-existent scan results', async () => {
      const response = await request(httpServer)
        .get('/api/scans/non-existent-scan-id/results')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
    });

    it('should require JWT authentication for scan results', async () => {
      if (!uploadedScanId) {
        console.warn('Skipping test - no uploaded scan available');
        return;
      }

      const response = await request(httpServer)
        .get(`/api/scans/${uploadedScanId}/results`)
        .expect(401);

      expect(response.body).toHaveProperty('statusCode', 401);
    });
  });

  describe('Data Consistency & Validation', () => {
    it('should maintain data consistency between upload and retrieval', async () => {
      const scanData = generateMockScanData();
      
      // Upload scan
      const uploadResponse = await request(httpServer)
        .post('/api/scans/upload')
        .set(createAuthHeaders.apiKey(validApiKey))
        .send(scanData)
        .expect(201);

      const scanId = uploadResponse.body.id;

      // Retrieve scan details
      const detailsResponse = await request(httpServer)
        .get(`/api/scans/${scanId}`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      // Verify data consistency
      expect(detailsResponse.body.name).toBe(scanData.name);
      expect(detailsResponse.body.scanType).toBe(scanData.scanType);
      expect(detailsResponse.body.totalFindings).toBe(scanData.scanData.findings.length);
    });

    it('should calculate metrics correctly from findings', async () => {
      const scanData = generateMockScanData();
      
      const response = await request(httpServer)
        .post('/api/scans/upload')
        .set(createAuthHeaders.apiKey(validApiKey))
        .send(scanData)
        .expect(201);

      // Verify calculated metrics match input data
      const expectedCritical = scanData.scanData.findings.filter(f => f.severity === 'Critical').length;
      const expectedHigh = scanData.scanData.findings.filter(f => f.severity === 'High').length;
      const expectedMedium = scanData.scanData.findings.filter(f => f.severity === 'Medium').length;
      const expectedLow = scanData.scanData.findings.filter(f => f.severity === 'Low').length;

      expect(response.body.criticalCount).toBe(expectedCritical);
      expect(response.body.highCount).toBe(expectedHigh);
      expect(response.body.mediumCount).toBe(expectedMedium);
      expect(response.body.lowCount).toBe(expectedLow);
    });
  });

  describe('Performance & Scalability', () => {
    it('should handle concurrent scan uploads', async () => {
      const scanPromises = Array.from({ length: 3 }, (_, i) => {
        const scanData = {
          ...generateMockScanData(),
          name: `Concurrent Scan ${i + 1}`
        };
        
        return request(httpServer)
          .post('/api/scans/upload')
          .set(createAuthHeaders.apiKey(validApiKey))
          .send(scanData);
      });

      const responses = await Promise.all(scanPromises);
      
      responses.forEach((response, i) => {
        expect(response.status).toBe(201);
        expect(response.body.name).toBe(`Concurrent Scan ${i + 1}`);
      });
    });

    it('should respond to scan list requests quickly', async () => {
      const startTime = Date.now();
      
      await request(httpServer)
        .get('/api/scans')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      const responseTime = Date.now() - startTime;
      expect(responseTime).toBeLessThan(2000); // Should respond within 2 seconds
    });
  });
});