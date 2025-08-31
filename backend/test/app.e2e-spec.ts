import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { 
  TEST_CONFIG, 
  AuthTestHelper, 
  createAuthHeaders,
  TestDatabaseHelper 
} from './setup-tests';
import { HttpExceptionFilter } from '../src/common/filters/http-exception.filter';

describe('IronVeil API - Health & Basic Functionality (e2e)', () => {
  let app: INestApplication;
  let httpServer: any;

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
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Health Check Endpoint', () => {
    it('GET /api - should return API health status', async () => {
      const response = await request(httpServer)
        .get('/api')
        .expect(200);

      expect(response.body).toMatchObject({
        message: expect.any(String),
        status: 'healthy',
        version: '1.0.0',
        timestamp: expect.any(String),
      });

      // Verify timestamp is a valid ISO string
      expect(new Date(response.body.timestamp).toISOString()).toBe(response.body.timestamp);
    });

    it('GET /api - should have proper CORS headers', async () => {
      const response = await request(httpServer)
        .get('/api')
        .set('Origin', TEST_CONFIG.frontendUrl);

      expect(response.headers['access-control-allow-origin']).toBe(TEST_CONFIG.frontendUrl);
      expect(response.headers['access-control-allow-credentials']).toBe('true');
    });

    it('GET /api - should respond within acceptable time', async () => {
      const startTime = Date.now();
      await request(httpServer)
        .get('/api')
        .expect(200);
      const responseTime = Date.now() - startTime;

      expect(responseTime).toBeLessThan(1000); // Should respond within 1 second
    });
  });

  describe('API Documentation', () => {
    it('GET /api/docs - should serve Swagger documentation', async () => {
      const response = await request(httpServer)
        .get('/api/docs')
        .expect(200);

      expect(response.headers['content-type']).toMatch(/text\/html/);
      expect(response.text).toContain('swagger-ui');
      expect(response.text).toContain('IronVeil API');
    });

    it('GET /api/docs-json - should provide OpenAPI specification', async () => {
      const response = await request(httpServer)
        .get('/api/docs-json')
        .expect(200);

      expect(response.body).toHaveProperty('openapi');
      expect(response.body).toHaveProperty('info');
      expect(response.body.info.title).toBe('IronVeil API');
      expect(response.body.info.version).toBe('1.0');
    });
  });

  describe('Error Handling', () => {
    it('GET /api/nonexistent - should return 404 for unknown routes', async () => {
      const response = await request(httpServer)
        .get('/api/nonexistent')
        .expect(404);

      expect(response.body).toHaveProperty('statusCode', 404);
      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('timestamp');
      expect(response.body).toHaveProperty('path', '/api/nonexistent');
    });

    it('POST /api/invalid - should handle validation errors', async () => {
      const response = await request(httpServer)
        .post('/api/invalid')
        .send({ invalid: 'data' })
        .expect(404); // Route doesn't exist, but validates error handling

      expect(response.body).toHaveProperty('statusCode');
      expect(response.body).toHaveProperty('timestamp');
    });
  });

  describe('Security Headers', () => {
    it('should not expose sensitive information in headers', async () => {
      const response = await request(httpServer)
        .get('/api')
        .expect(200);

      // Should not expose internal server information
      expect(response.headers['x-powered-by']).toBeUndefined();
      expect(response.headers['server']).not.toContain('Express');
    });

    it('should handle malicious requests gracefully', async () => {
      const maliciousHeaders = {
        'X-Forwarded-For': '127.0.0.1; DROP TABLE users;--',
        'User-Agent': '<script>alert("xss")</script>',
        'X-Real-IP': '../../etc/passwd',
      };

      const response = await request(httpServer)
        .get('/api')
        .set(maliciousHeaders)
        .expect(200);

      expect(response.body.status).toBe('healthy');
    });
  });
});
