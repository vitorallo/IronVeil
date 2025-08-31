import { Test } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

// Global test configuration
export const TEST_CONFIG = {
  // Test user credentials
  testUser: {
    email: 'test2@ironveil.local',
    password: 'nokia347',
    userId: 'test-user-id-123',
    organizationId: 'test-org-id-456'
  },
  
  // API endpoints
  baseUrl: 'http://localhost:3001',
  frontendUrl: 'http://localhost:3002',
  supabaseUrl: 'http://127.0.0.1:54321',
  
  // Test API keys
  validApiKey: 'iv_test_api_key_for_desktop_scanner_12345678',
  invalidApiKey: 'iv_invalid_api_key_xyz',
  
  // Test JWT tokens (will be generated during tests)
  validJwtToken: null as string | null,
  invalidJwtToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpbnZhbGlkIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid',
  
  // Test timeouts
  requestTimeout: 10000,
  authTimeout: 5000,
};

// Test data generators
export const generateMockScanData = () => ({
  name: `Test Scan ${Date.now()}`,
  scanType: 'hybrid',
  scanData: {
    metadata: {
      scanId: `scan-${Date.now()}`,
      timestamp: new Date().toISOString(),
      domain: 'test.domain.com',
      tenantId: 'test-tenant-id',
      executionTime: 120.5,
      rulesetVersion: '1.0.0',
      scannerVersion: '1.0.0'
    },
    findings: [
      {
        ruleId: 'AD-T1-006',
        severity: 'Critical',
        category: 'delegation',
        description: 'Unconstrained delegation detected',
        affectedObjects: ['TestComputer01', 'TestComputer02'],
        score: 100,
        impact: 95,
        remediation: 'Remove unconstrained delegation from computer accounts'
      },
      {
        ruleId: 'AD-T3-003',
        severity: 'High',
        category: 'accounts',
        description: 'Stale privileged accounts found',
        affectedObjects: ['AdminUser01', 'ServiceAccount02'],
        score: 75,
        impact: 80,
        remediation: 'Disable or remove unused privileged accounts'
      },
      {
        ruleId: 'ENT-AUTH-001',
        severity: 'Medium',
        category: 'authentication',
        description: 'MFA not enforced for privileged users',
        affectedObjects: ['admin@test.com', 'globaladmin@test.com'],
        score: 50,
        impact: 60,
        remediation: 'Enable MFA requirement for all privileged accounts'
      }
    ],
    summary: {
      totalFindings: 3,
      criticalCount: 1,
      highCount: 1,
      mediumCount: 1,
      lowCount: 0,
      overallScore: 75,
      riskLevel: 'HIGH'
    }
  }
});

export const generateMockOrganization = () => ({
  id: TEST_CONFIG.testUser.organizationId,
  name: 'Test Organization',
  tier: 'community',
  settings: {
    scanRetentionDays: 90,
    maxScansPerMonth: 100,
    enableRealTimeUpdates: true
  }
});

// Authentication helpers
export class AuthTestHelper {
  static async getValidJwtToken(): Promise<string> {
    if (TEST_CONFIG.validJwtToken) {
      return TEST_CONFIG.validJwtToken;
    }
    
    // In a real test, this would authenticate with Supabase
    // For now, we'll return a mock token that the backend can validate
    return 'mock-jwt-token-for-testing';
  }
  
  static getValidApiKey(): string {
    return TEST_CONFIG.validApiKey;
  }
  
  static getInvalidApiKey(): string {
    return TEST_CONFIG.invalidApiKey;
  }
  
  static getInvalidJwtToken(): string {
    return TEST_CONFIG.invalidJwtToken;
  }
}

// HTTP request helpers
export const createAuthHeaders = {
  jwt: (token: string) => ({
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }),
  
  apiKey: (apiKey: string) => ({
    'X-API-Key': apiKey,
    'Content-Type': 'application/json'
  }),
  
  basic: () => ({
    'Content-Type': 'application/json'
  })
};

// Test database helpers
export class TestDatabaseHelper {
  static async cleanupTestData() {
    // In a real implementation, this would clean up test data from the database
    console.log('Cleaning up test data...');
  }
  
  static async seedTestData() {
    // In a real implementation, this would seed the database with test data
    console.log('Seeding test data...');
  }
}

// Jest setup and teardown
beforeAll(async () => {
  console.log('🧪 Setting up IronVeil API Test Suite');
  console.log(`📡 Backend API: ${TEST_CONFIG.baseUrl}`);
  console.log(`🌐 Frontend: ${TEST_CONFIG.frontendUrl}`);
  console.log(`🗄️ Supabase: ${TEST_CONFIG.supabaseUrl}`);
  
  await TestDatabaseHelper.seedTestData();
});

afterAll(async () => {
  console.log('🧹 Cleaning up after tests');
  await TestDatabaseHelper.cleanupTestData();
});

// Global error handler for tests
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});