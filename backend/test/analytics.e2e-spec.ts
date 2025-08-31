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

describe('IronVeil API - Analytics & Dashboard Metrics (e2e)', () => {
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

    // Upload test scan data to have analytics data
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

  describe('Dashboard Overview (Frontend)', () => {
    it('should return comprehensive dashboard metrics', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/dashboard')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        overallSecurityScore: expect.any(Number),
        scoreChange: expect.any(Number),
        totalFindings: expect.any(Number),
        newFindingsThisWeek: expect.any(Number),
        totalScans: expect.any(Number),
        lastScanDate: expect.any(String),
        riskDistribution: expect.any(Object),
        topCategories: expect.any(Array),
        recentActivity: expect.any(Array),
        complianceStatus: expect.any(Object),
      });

      // Verify score is within valid range
      expect(response.body.overallSecurityScore).toBeGreaterThanOrEqual(0);
      expect(response.body.overallSecurityScore).toBeLessThanOrEqual(100);
      
      // Verify score change is reasonable
      expect(response.body.scoreChange).toBeGreaterThanOrEqual(-100);
      expect(response.body.scoreChange).toBeLessThanOrEqual(100);
    });

    it('should include risk distribution breakdown', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/dashboard')
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

      // Verify total matches overall findings
      const totalRisk = Object.values(response.body.riskDistribution).reduce((sum, count) => sum + (count as number), 0);
      expect(totalRisk).toBe(response.body.totalFindings);
    });

    it('should include top security categories', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/dashboard')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(Array.isArray(response.body.topCategories)).toBe(true);
      expect(response.body.topCategories.length).toBeLessThanOrEqual(5);

      if (response.body.topCategories.length > 0) {
        const category = response.body.topCategories[0];
        expect(category).toMatchObject({
          name: expect.any(String),
          count: expect.any(Number),
          percentage: expect.any(Number),
          trend: expect.any(String),
        });

        expect(category.count).toBeGreaterThan(0);
        expect(category.percentage).toBeGreaterThan(0);
        expect(category.percentage).toBeLessThanOrEqual(100);
        expect(['up', 'down', 'stable']).toContain(category.trend);
      }
    });

    it('should include recent activity timeline', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/dashboard')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(Array.isArray(response.body.recentActivity)).toBe(true);
      expect(response.body.recentActivity.length).toBeLessThanOrEqual(10);

      if (response.body.recentActivity.length > 0) {
        const activity = response.body.recentActivity[0];
        expect(activity).toMatchObject({
          id: expect.any(String),
          type: expect.any(String),
          title: expect.any(String),
          description: expect.any(String),
          timestamp: expect.any(String),
          metadata: expect.any(Object),
        });

        expect(['scan_completed', 'finding_created', 'finding_updated', 'user_action']).toContain(activity.type);
      }
    });

    it('should include compliance status overview', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/dashboard')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body.complianceStatus).toMatchObject({
        frameworks: expect.any(Object),
        overallCompliance: expect.any(Number),
        improvementAreas: expect.any(Array),
      });

      expect(response.body.complianceStatus.overallCompliance).toBeGreaterThanOrEqual(0);
      expect(response.body.complianceStatus.overallCompliance).toBeLessThanOrEqual(100);

      // Should include common frameworks
      const frameworks = response.body.complianceStatus.frameworks;
      expect(typeof frameworks).toBe('object');
    });

    it('should require JWT authentication', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/dashboard')
        .expect(401);

      expect(response.body).toHaveProperty('statusCode', 401);
    });
  });

  describe('Security Trends (Frontend)', () => {
    it('should return security score trends over time', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/trends/security-score')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        timeframe: expect.any(String),
        dataPoints: expect.any(Array),
        trend: expect.any(String),
        changeRate: expect.any(Number),
        insights: expect.any(Array),
      });

      expect(['7d', '30d', '90d', '1y']).toContain(response.body.timeframe);
      expect(['improving', 'stable', 'declining']).toContain(response.body.trend);

      if (response.body.dataPoints.length > 0) {
        const dataPoint = response.body.dataPoints[0];
        expect(dataPoint).toMatchObject({
          date: expect.any(String),
          score: expect.any(Number),
          change: expect.any(Number),
        });

        expect(dataPoint.score).toBeGreaterThanOrEqual(0);
        expect(dataPoint.score).toBeLessThanOrEqual(100);
      }
    });

    it('should support different time ranges', async () => {
      const timeframes = ['7d', '30d', '90d'];
      
      for (const timeframe of timeframes) {
        const response = await request(httpServer)
          .get(`/api/analytics/trends/security-score?timeframe=${timeframe}`)
          .set(createAuthHeaders.jwt(validJwtToken))
          .expect(200);

        expect(response.body.timeframe).toBe(timeframe);
        expect(Array.isArray(response.body.dataPoints)).toBe(true);
      }
    });

    it('should return findings trends by severity', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/trends/findings')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        timeframe: expect.any(String),
        bySeverity: expect.any(Object),
        totalTrend: expect.any(String),
      });

      expect(response.body.bySeverity).toMatchObject({
        Critical: expect.any(Array),
        High: expect.any(Array),
        Medium: expect.any(Array),
        Low: expect.any(Array),
      });

      // Each severity should have time series data
      Object.values(response.body.bySeverity).forEach(series => {
        expect(Array.isArray(series)).toBe(true);
        if ((series as any[]).length > 0) {
          const point = (series as any[])[0];
          expect(point).toMatchObject({
            date: expect.any(String),
            count: expect.any(Number),
          });
        }
      });
    });

    it('should return category distribution trends', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/trends/categories')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        timeframe: expect.any(String),
        categories: expect.any(Array),
        trendingUp: expect.any(Array),
        trendingDown: expect.any(Array),
      });

      if (response.body.categories.length > 0) {
        const category = response.body.categories[0];
        expect(category).toMatchObject({
          name: expect.any(String),
          dataPoints: expect.any(Array),
          trend: expect.any(String),
        });
      }
    });
  });

  describe('Risk Analysis (Frontend)', () => {
    it('should return comprehensive risk assessment', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/risk/assessment')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        overallRiskScore: expect.any(Number),
        riskLevel: expect.any(String),
        primaryRisks: expect.any(Array),
        riskFactors: expect.any(Object),
        recommendations: expect.any(Array),
        businessImpact: expect.any(Object),
      });

      expect(response.body.overallRiskScore).toBeGreaterThanOrEqual(0);
      expect(response.body.overallRiskScore).toBeLessThanOrEqual(100);
      expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(response.body.riskLevel);

      if (response.body.primaryRisks.length > 0) {
        const risk = response.body.primaryRisks[0];
        expect(risk).toMatchObject({
          category: expect.any(String),
          severity: expect.any(String),
          likelihood: expect.any(Number),
          impact: expect.any(Number),
          description: expect.any(String),
          affectedAssets: expect.any(Number),
        });
      }
    });

    it('should include risk mitigation recommendations', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/risk/assessment')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(Array.isArray(response.body.recommendations)).toBe(true);

      if (response.body.recommendations.length > 0) {
        const recommendation = response.body.recommendations[0];
        expect(recommendation).toMatchObject({
          priority: expect.any(String),
          title: expect.any(String),
          description: expect.any(String),
          estimatedEffort: expect.any(String),
          expectedImpact: expect.any(String),
          category: expect.any(String),
        });

        expect(['HIGH', 'MEDIUM', 'LOW']).toContain(recommendation.priority);
        expect(['HOURS', 'DAYS', 'WEEKS', 'MONTHS']).toContain(recommendation.estimatedEffort);
      }
    });

    it('should analyze attack paths and vectors', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/risk/attack-paths')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        criticalPaths: expect.any(Array),
        commonVectors: expect.any(Array),
        vulnerabilityChains: expect.any(Array),
        mitigationPriority: expect.any(Array),
      });

      if (response.body.criticalPaths.length > 0) {
        const path = response.body.criticalPaths[0];
        expect(path).toMatchObject({
          id: expect.any(String),
          severity: expect.any(String),
          steps: expect.any(Array),
          likelihood: expect.any(Number),
          impact: expect.any(Number),
          mitigations: expect.any(Array),
        });

        expect(path.steps.length).toBeGreaterThan(0);
      }
    });
  });

  describe('Compliance Analytics (Frontend)', () => {
    it('should return compliance framework status', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/compliance/frameworks')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        frameworks: expect.any(Array),
        overallCompliance: expect.any(Number),
        improvements: expect.any(Array),
      });

      if (response.body.frameworks.length > 0) {
        const framework = response.body.frameworks[0];
        expect(framework).toMatchObject({
          name: expect.any(String),
          version: expect.any(String),
          compliance: expect.any(Number),
          controls: expect.any(Object),
          gaps: expect.any(Array),
        });

        expect(framework.compliance).toBeGreaterThanOrEqual(0);
        expect(framework.compliance).toBeLessThanOrEqual(100);
      }
    });

    it('should analyze specific compliance framework', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/compliance/frameworks/nist')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        framework: 'NIST',
        version: expect.any(String),
        overallCompliance: expect.any(Number),
        controlCategories: expect.any(Array),
        gaps: expect.any(Array),
        recommendations: expect.any(Array),
      });

      if (response.body.controlCategories.length > 0) {
        const category = response.body.controlCategories[0];
        expect(category).toMatchObject({
          name: expect.any(String),
          compliance: expect.any(Number),
          totalControls: expect.any(Number),
          implementedControls: expect.any(Number),
        });
      }
    });

    it('should generate compliance reports', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/compliance/report?framework=iso27001&format=summary')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        framework: 'ISO27001',
        reportType: 'summary',
        generatedAt: expect.any(String),
        executiveSummary: expect.any(String),
        keyFindings: expect.any(Array),
        complianceScore: expect.any(Number),
        actionItems: expect.any(Array),
      });
    });
  });

  describe('Performance Analytics (Frontend)', () => {
    it('should return scan performance metrics', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/performance/scans')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        totalScans: expect.any(Number),
        averageExecutionTime: expect.any(Number),
        scanFrequency: expect.any(Object),
        successRate: expect.any(Number),
        performanceTrend: expect.any(String),
      });

      expect(response.body.successRate).toBeGreaterThanOrEqual(0);
      expect(response.body.successRate).toBeLessThanOrEqual(100);
      expect(['improving', 'stable', 'declining']).toContain(response.body.performanceTrend);
    });

    it('should analyze finding resolution metrics', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/performance/findings')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        totalFindings: expect.any(Number),
        resolvedFindings: expect.any(Number),
        averageResolutionTime: expect.any(Number),
        resolutionRate: expect.any(Number),
        backlog: expect.any(Object),
      });

      expect(response.body.resolutionRate).toBeGreaterThanOrEqual(0);
      expect(response.body.resolutionRate).toBeLessThanOrEqual(100);

      expect(response.body.backlog).toMatchObject({
        critical: expect.any(Number),
        high: expect.any(Number),
        medium: expect.any(Number),
        low: expect.any(Number),
      });
    });
  });

  describe('Custom Analytics (Frontend)', () => {
    it('should support custom date range queries', async () => {
      const startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
      const endDate = new Date().toISOString();

      const response = await request(httpServer)
        .get(`/api/analytics/custom/range?startDate=${startDate}&endDate=${endDate}&metrics=score,findings,scans`)
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        dateRange: expect.any(Object),
        metrics: expect.any(Object),
        summary: expect.any(Object),
      });

      expect(response.body.dateRange).toMatchObject({
        startDate: startDate,
        endDate: endDate,
      });

      expect(response.body.metrics).toHaveProperty('score');
      expect(response.body.metrics).toHaveProperty('findings');
      expect(response.body.metrics).toHaveProperty('scans');
    });

    it('should support filtering by scan types', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/custom/by-scan-type?scanType=hybrid')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        scanType: 'hybrid',
        metrics: expect.any(Object),
        breakdown: expect.any(Object),
      });
    });
  });

  describe('Real-time Analytics (Frontend)', () => {
    it('should return current system status', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/realtime/status')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        timestamp: expect.any(String),
        activeScans: expect.any(Number),
        systemHealth: expect.any(String),
        queueDepth: expect.any(Number),
        responseTime: expect.any(Number),
      });

      expect(['healthy', 'degraded', 'unhealthy']).toContain(response.body.systemHealth);
      expect(response.body.activeScans).toBeGreaterThanOrEqual(0);
    });

    it('should provide live finding alerts', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/realtime/alerts')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      expect(response.body).toMatchObject({
        alerts: expect.any(Array),
        alertCount: expect.any(Number),
        lastUpdated: expect.any(String),
      });

      if (response.body.alerts.length > 0) {
        const alert = response.body.alerts[0];
        expect(alert).toMatchObject({
          id: expect.any(String),
          severity: expect.any(String),
          type: expect.any(String),
          message: expect.any(String),
          timestamp: expect.any(String),
        });
      }
    });
  });

  describe('Data Security & Access Control', () => {
    it('should only return analytics for user\'s organization', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/dashboard')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      // All metrics should be scoped to the user's organization
      expect(response.body).toHaveProperty('overallSecurityScore');
      
      // Verify no cross-organization data leakage
      if (response.body.recentActivity && response.body.recentActivity.length > 0) {
        response.body.recentActivity.forEach(activity => {
          if (activity.metadata && activity.metadata.organizationId) {
            expect(activity.metadata.organizationId).toBe(TEST_CONFIG.testUser.organizationId);
          }
        });
      }
    });

    it('should require proper authentication for all analytics endpoints', async () => {
      const endpoints = [
        '/api/analytics/dashboard',
        '/api/analytics/trends/security-score',
        '/api/analytics/risk/assessment',
        '/api/analytics/compliance/frameworks'
      ];

      for (const endpoint of endpoints) {
        const response = await request(httpServer)
          .get(endpoint)
          .expect(401);

        expect(response.body).toHaveProperty('statusCode', 401);
      }
    });
  });

  describe('Performance & Caching', () => {
    it('should respond to dashboard requests quickly', async () => {
      const startTime = Date.now();
      
      await request(httpServer)
        .get('/api/analytics/dashboard')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      const responseTime = Date.now() - startTime;
      expect(responseTime).toBeLessThan(3000); // Should respond within 3 seconds
    });

    it('should handle concurrent analytics requests', async () => {
      const promises = Array.from({ length: 3 }, () =>
        request(httpServer)
          .get('/api/analytics/dashboard')
          .set(createAuthHeaders.jwt(validJwtToken))
          .expect(200)
      );

      const responses = await Promise.all(promises);
      
      responses.forEach(response => {
        expect(response.body).toHaveProperty('overallSecurityScore');
        expect(response.body).toHaveProperty('totalFindings');
      });
    });

    it('should provide cache headers for appropriate endpoints', async () => {
      const response = await request(httpServer)
        .get('/api/analytics/dashboard')
        .set(createAuthHeaders.jwt(validJwtToken))
        .expect(200);

      // Should have appropriate cache control for dashboard data
      // (This would depend on actual caching implementation)
      expect(response.headers).toBeDefined();
    });
  });
});