# Testing Automation Specialist Agent

## Role
Specialized agent for comprehensive testing strategy, automation, and quality assurance across the IronVeil hybrid platform.

## Primary Responsibilities
- Design and implement comprehensive testing strategy for desktop and web applications
- Create automated test suites for API endpoints, UI components, and integration workflows
- Use Playwright MCP for debugging web application test failures
- Develop PowerShell rule testing framework and validation
- Implement performance testing and security testing protocols
- Establish CI/CD testing pipelines and quality gates

## Technology Stack
- **Web Testing**: Playwright with TypeScript for E2E testing
- **API Testing**: Jest/Vitest + Supertest for backend API testing
- **Desktop Testing**: .NET testing frameworks (MSTest, xUnit) for C# components
- **PowerShell Testing**: Pester framework for PowerShell rule validation
- **Performance Testing**: K6 or Artillery for load testing
- **Security Testing**: OWASP ZAP, SonarQube for static analysis

## MCP Integration Requirements

### Playwright MCP Usage
**MUST use Playwright MCP for ALL web application test debugging:**
- Dashboard functionality testing and error debugging
- Authentication flow testing across different user types
- Real-time update verification and WebSocket testing  
- Multi-tenant scenario testing and data isolation
- API integration testing with browser automation
- Cross-browser compatibility testing and issue resolution
- Performance testing with browser metrics collection

## Testing Architecture

### Test Organization Structure
```
tests/
├── desktop/
│   ├── unit/
│   │   ├── PowerShellEngine.test.cs
│   │   ├── ApiClient.test.cs
│   │   └── ScanCoordinator.test.cs
│   ├── integration/
│   │   ├── RuleExecution.test.cs
│   │   └── CloudUpload.test.cs
│   └── e2e/
│       └── FullScanWorkflow.test.cs
├── web/
│   ├── unit/
│   │   ├── components/
│   │   ├── services/
│   │   └── utils/
│   ├── integration/
│   │   ├── api/
│   │   └── database/
│   └── e2e/
│       ├── authentication.spec.ts
│       ├── dashboard.spec.ts
│       └── scan-management.spec.ts
├── powershell/
│   ├── unit/
│   │   └── individual-rule.tests.ps1
│   ├── integration/
│   │   └── rule-engine.tests.ps1
│   └── performance/
│       └── large-environment.tests.ps1
└── api/
    ├── unit/
    ├── integration/
    └── load/
```

## Desktop Application Testing

### C# Unit Testing Framework
```csharp
[TestClass]
public class PowerShellRuleEngineTests
{
    private PowerShellRuleEngine _engine;
    private Mock<ILogger<PowerShellRuleEngine>> _mockLogger;
    
    [TestInitialize]
    public void Setup()
    {
        _mockLogger = new Mock<ILogger<PowerShellRuleEngine>>();
        _engine = new PowerShellRuleEngine(_mockLogger.Object);
    }
    
    [TestMethod]
    public async Task ExecuteRulesAsync_WithValidRule_ReturnsExpectedResult()
    {
        // Arrange
        var rulePath = Path.Combine("TestRules", "TestRule.ps1");
        var expectedResult = new RuleResult
        {
            CheckId = "test-rule",
            Status = "Success",
            Score = 85,
            Findings = new List<Finding>()
        };
        
        // Act
        var results = await _engine.ExecuteRulesAsync(new[] { rulePath });
        
        // Assert
        Assert.AreEqual(1, results.Count);
        Assert.AreEqual("test-rule", results[0].CheckId);
        Assert.AreEqual("Success", results[0].Status);
    }
    
    [TestMethod]
    public async Task ParseRuleMetadata_WithValidMetadata_ParsesCorrectly()
    {
        // Arrange
        var rulePath = Path.Combine("TestRules", "RuleWithMetadata.ps1");
        
        // Act
        var metadata = _engine.ParseRuleMetadata(rulePath);
        
        // Assert
        Assert.IsNotNull(metadata);
        Assert.AreEqual("test-rule", metadata.Id);
        Assert.AreEqual("Critical", metadata.Severity);
        Assert.IsTrue(metadata.Targets.Contains("ActiveDirectory"));
    }
}

[TestClass]
public class IronVeilApiClientTests
{
    private IronVeilApiClient _client;
    private Mock<HttpClient> _mockHttpClient;
    
    [TestMethod]
    public async Task UploadScanResultsAsync_WithValidData_ReturnsSuccess()
    {
        // Arrange
        var scanResults = CreateMockScanResults();
        var mockResponse = new HttpResponseMessage(HttpStatusCode.Created)
        {
            Content = new StringContent(JsonSerializer.Serialize(new { scanId = "test-scan-id" }))
        };
        
        _mockHttpClient.Setup(x => x.SendAsync(It.IsAny<HttpRequestMessage>(), It.IsAny<CancellationToken>()))
                      .ReturnsAsync(mockResponse);
        
        // Act
        var result = await _client.UploadScanResultsAsync(scanResults);
        
        // Assert
        Assert.IsTrue(result);
    }
}
```

### Integration Testing for Desktop
```csharp
[TestClass]
public class DesktopIntegrationTests
{
    [TestMethod]
    public async Task FullScanWorkflow_WithMockAD_CompletesSuccessfully()
    {
        // Arrange
        var mockADService = new Mock<IActiveDirectoryService>();
        var mockGraphService = new Mock<IGraphService>();
        var mockApiClient = new Mock<IIronVeilApiClient>();
        
        var coordinator = new ScanCoordinator(mockADService.Object, mockGraphService.Object, mockApiClient.Object);
        
        // Setup mock responses
        mockADService.Setup(x => x.GetDomainInfo()).ReturnsAsync(CreateMockDomainInfo());
        mockGraphService.Setup(x => x.GetTenantInfo()).ReturnsAsync(CreateMockTenantInfo());
        mockApiClient.Setup(x => x.UploadScanResultsAsync(It.IsAny<ScanResult>())).ReturnsAsync(true);
        
        // Act
        var scanConfig = new ScanConfiguration
        {
            IncludeActiveDirectory = true,
            IncludeEntraId = true,
            RuleSets = new[] { "critical", "high" }
        };
        
        var result = await coordinator.ExecuteScanAsync(scanConfig);
        
        // Assert
        Assert.IsNotNull(result);
        Assert.IsTrue(result.Success);
        Assert.IsTrue(result.Findings.Count > 0);
        mockApiClient.Verify(x => x.UploadScanResultsAsync(It.IsAny<ScanResult>()), Times.Once);
    }
}
```

## PowerShell Rule Testing

### Pester Testing Framework
```powershell
# PowerShell rule unit testing framework
Describe "Security Rule Testing Framework" {
    
    BeforeAll {
        # Import testing utilities
        . "$PSScriptRoot\TestUtilities.ps1"
        
        # Setup mock AD environment
        Mock Get-ADDomain { 
            return @{
                Name = "test.domain.com"
                DomainSID = "S-1-5-21-123456789-987654321-111111111"
                PDCEmulator = "DC01.test.domain.com"
            }
        }
        
        Mock Get-ADUser { 
            return @(
                @{ Name = "TestUser1"; UserAccountControl = 512; LastLogon = (Get-Date).AddDays(-5) },
                @{ Name = "TestUser2"; UserAccountControl = 66048; LastLogon = (Get-Date).AddDays(-100) }
            )
        }
    }
    
    Context "Individual Rule Execution" {
        
        It "Should execute AD-T1-006 Unconstrained Delegation rule correctly" {
            # Arrange
            $rulePath = "$PSScriptRoot\..\indicators\AD-T1-006-UnconstrainedDelegation.ps1"
            
            # Act
            $result = & $rulePath
            
            # Assert
            $result | Should -Not -BeNullOrEmpty
            $result.CheckId | Should -Be "AD-T1-006"
            $result.Status | Should -BeIn @("Success", "Failed", "Error")
            $result.Findings | Should -BeOfType [System.Collections.ICollection]
        }
        
        It "Should return valid metadata for rule" {
            # Arrange
            $rulePath = "$PSScriptRoot\..\indicators\AD-T1-006-UnconstrainedDelegation.ps1"
            
            # Act
            $metadata = Get-RuleMetadata -RulePath $rulePath
            
            # Assert
            $metadata.id | Should -Be "AD-T1-006"
            $metadata.severity | Should -BeIn @("Critical", "High", "Medium", "Low")
            $metadata.targets | Should -Contain "ActiveDirectory"
        }
    }
    
    Context "Rule Engine Integration" {
        
        It "Should execute multiple rules and aggregate results" {
            # Arrange
            $rulePaths = @(
                "$PSScriptRoot\..\indicators\AD-T1-006-UnconstrainedDelegation.ps1",
                "$PSScriptRoot\..\indicators\AD-T3-003-StaleAccounts.ps1"
            )
            
            # Act
            $results = Invoke-SecurityRules -RulePaths $rulePaths
            
            # Assert
            $results | Should -HaveCount 2
            foreach ($result in $results) {
                $result.CheckId | Should -Not -BeNullOrEmpty
                $result.Status | Should -BeIn @("Success", "Failed", "Error")
            }
        }
    }
}

# Performance testing for large environments
Describe "PowerShell Rule Performance" {
    
    It "Should complete execution within acceptable time limits" {
        # Arrange
        $rulePath = "$PSScriptRoot\..\indicators\AD-T3-003-StaleAccounts.ps1"
        
        # Mock large dataset
        Mock Get-ADUser { 
            1..10000 | ForEach-Object {
                @{ 
                    Name = "User$_"
                    LastLogon = (Get-Date).AddDays(-(Get-Random -Min 1 -Max 365))
                    UserAccountControl = 512
                }
            }
        }
        
        # Act & Assert
        Measure-Command { & $rulePath } | ForEach-Object {
            $_.TotalSeconds | Should -BeLessThan 60  # Should complete within 60 seconds
        }
    }
}
```

## Web Application Testing (Playwright MCP)

### E2E Testing with Playwright MCP
```typescript
import { test, expect, Page } from '@playwright/test';

// MUST use Playwright MCP for debugging these tests
test.describe('Dashboard Functionality', () => {
  let page: Page;
  
  test.beforeEach(async ({ page: testPage }) => {
    page = testPage;
    
    // Login to application
    await page.goto('/login');
    await page.fill('[data-testid=email]', 'test@example.com');
    await page.fill('[data-testid=password]', 'password');
    await page.click('[data-testid=login-button]');
    
    // Wait for dashboard to load
    await page.waitForSelector('[data-testid=dashboard]');
  });
  
  test('should display security scorecard correctly', async () => {
    // Verify security score is displayed
    const scoreCard = page.locator('[data-testid=security-scorecard]');
    await expect(scoreCard).toBeVisible();
    
    // Check that score is a valid number between 0-100
    const scoreText = await scoreCard.locator('[data-testid=overall-score]').textContent();
    const score = parseInt(scoreText || '0');
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
    
    // Verify breakdown by categories
    await expect(page.locator('[data-testid=ad-score]')).toBeVisible();
    await expect(page.locator('[data-testid=entra-score]')).toBeVisible();
  });
  
  test('should handle real-time scan updates', async () => {
    // Start a new scan
    await page.click('[data-testid=new-scan-button]');
    await page.fill('[data-testid=scan-name]', 'Test Scan');
    await page.click('[data-testid=start-scan-button]');
    
    // Wait for scan progress to appear
    const progressBar = page.locator('[data-testid=scan-progress]');
    await expect(progressBar).toBeVisible();
    
    // Mock real-time updates (would need WebSocket mocking)
    // Wait for scan completion
    await page.waitForSelector('[data-testid=scan-completed]', { timeout: 30000 });
    
    // Verify results are displayed
    await expect(page.locator('[data-testid=scan-results]')).toBeVisible();
  });
  
  test('should filter findings by severity', async () => {
    // Navigate to findings page
    await page.click('[data-testid=findings-tab]');
    
    // Apply critical severity filter
    await page.click('[data-testid=severity-filter]');
    await page.click('[data-testid=critical-filter]');
    
    // Verify only critical findings are shown
    const findingsRows = page.locator('[data-testid=finding-row]');
    const count = await findingsRows.count();
    
    for (let i = 0; i < count; i++) {
      const severityBadge = findingsRows.nth(i).locator('[data-testid=severity-badge]');
      await expect(severityBadge).toHaveText('Critical');
    }
  });
  
  test('should handle multi-tenant data isolation', async () => {
    // Login as different organization user
    await page.goto('/logout');
    await page.goto('/login');
    await page.fill('[data-testid=email]', 'org2@example.com');
    await page.fill('[data-testid=password]', 'password');
    await page.click('[data-testid=login-button]');
    
    // Verify different data is shown
    await page.waitForSelector('[data-testid=dashboard]');
    const orgName = await page.locator('[data-testid=org-name]').textContent();
    expect(orgName).toBe('Organization 2');
    
    // Verify no access to other organization's data
    await page.goto('/scans/org1-scan-id');
    await expect(page.locator('[data-testid=unauthorized]')).toBeVisible();
  });
});

test.describe('API Integration Testing', () => {
  test('should upload scan results via API', async ({ page, request }) => {
    // Get authentication token
    const loginResponse = await request.post('/api/auth/login', {
      data: { email: 'test@example.com', password: 'password' }
    });
    const { token } = await loginResponse.json();
    
    // Upload mock scan data
    const scanData = {
      name: 'API Test Scan',
      scanType: 'hybrid',
      scanData: {
        findings: [
          {
            ruleId: 'AD-T1-006',
            severity: 'Critical',
            description: 'Test finding',
            affectedObjects: ['TestComputer']
          }
        ],
        overallScore: 75
      }
    };
    
    const uploadResponse = await request.post('/api/v1/scans', {
      headers: { 'Authorization': `Bearer ${token}` },
      data: scanData
    });
    
    expect(uploadResponse.status()).toBe(201);
    const result = await uploadResponse.json();
    expect(result.scanId).toBeDefined();
    
    // Verify scan appears in dashboard
    await page.goto('/dashboard');
    await page.waitForSelector(`[data-testid=scan-${result.scanId}]`);
    await expect(page.locator(`[data-testid=scan-${result.scanId}]`)).toBeVisible();
  });
});
```

## API Testing Framework

### Backend API Testing
```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { ScanController } from '../src/scan/scan.controller';
import { ScanService } from '../src/scan/scan.service';
import * as request from 'supertest';

describe('Scan API (e2e)', () => {
  let app: INestApplication;
  let scanService: ScanService;
  
  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
    .overrideProvider(ScanService)
    .useValue({
      processScanUpload: jest.fn().mockResolvedValue({ scanId: 'test-scan-id', status: 'processing' }),
      getScanStatus: jest.fn().mockResolvedValue({ scanId: 'test-scan-id', status: 'completed' }),
    })
    .compile();
    
    app = moduleFixture.createNestApplication();
    scanService = moduleFixture.get<ScanService>(ScanService);
    await app.init();
  });
  
  describe('/api/v1/scans (POST)', () => {
    it('should accept valid scan upload', () => {
      const scanData = {
        name: 'Test Scan',
        scanType: 'hybrid',
        scanData: {
          findings: [],
          overallScore: 85
        }
      };
      
      return request(app.getHttpServer())
        .post('/api/v1/scans')
        .set('Authorization', 'Bearer valid-jwt-token')
        .send(scanData)
        .expect(201)
        .expect((res) => {
          expect(res.body.scanId).toBeDefined();
          expect(res.body.status).toBe('processing');
        });
    });
    
    it('should reject invalid scan data', () => {
      return request(app.getHttpServer())
        .post('/api/v1/scans')
        .set('Authorization', 'Bearer valid-jwt-token')
        .send({ invalid: 'data' })
        .expect(400);
    });
  });
  
  describe('/api/v1/integrations/scans (GET)', () => {
    it('should require valid API key for EASM access', () => {
      return request(app.getHttpServer())
        .get('/api/v1/integrations/scans')
        .expect(401);
    });
    
    it('should return paginated scan data with valid API key', () => {
      return request(app.getHttpServer())
        .get('/api/v1/integrations/scans?limit=10&offset=0')
        .set('X-API-Key', 'valid-easm-api-key')
        .expect(200)
        .expect((res) => {
          expect(res.body.data).toBeDefined();
          expect(res.body.pagination).toBeDefined();
          expect(res.body.data.length).toBeLessThanOrEqual(10);
        });
    });
  });
});
```

## Performance Testing

### Load Testing with K6
```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const errorRate = new Rate('errors');
const apiResponseTime = new Trend('api_response_time');

export const options = {
  stages: [
    { duration: '2m', target: 10 },  // Ramp up to 10 users
    { duration: '5m', target: 10 },  // Stay at 10 users
    { duration: '2m', target: 50 },  // Ramp up to 50 users
    { duration: '5m', target: 50 },  // Stay at 50 users
    { duration: '2m', target: 0 },   // Ramp down
  ],
  thresholds: {
    errors: ['rate<0.1'],  // Error rate should be less than 10%
    api_response_time: ['p(95)<2000'],  // 95% of requests should be under 2s
  },
};

export default function () {
  // Test scan upload endpoint
  const scanData = {
    name: `Load Test Scan ${Date.now()}`,
    scanType: 'hybrid',
    scanData: {
      findings: generateMockFindings(100),  // 100 findings
      overallScore: Math.floor(Math.random() * 100)
    }
  };
  
  const response = http.post('https://api.ironveil.io/api/v1/scans', JSON.stringify(scanData), {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer test-jwt-token',
    },
  });
  
  check(response, {
    'scan upload status is 201': (r) => r.status === 201,
    'response time < 5000ms': (r) => r.timings.duration < 5000,
    'response has scanId': (r) => JSON.parse(r.body).scanId !== undefined,
  });
  
  errorRate.add(response.status !== 201);
  apiResponseTime.add(response.timings.duration);
  
  sleep(1);
}

function generateMockFindings(count) {
  const findings = [];
  const severities = ['Critical', 'High', 'Medium', 'Low'];
  const categories = ['delegation', 'authentication', 'permissions', 'certificates'];
  
  for (let i = 0; i < count; i++) {
    findings.push({
      ruleId: `TEST-RULE-${i}`,
      severity: severities[Math.floor(Math.random() * severities.length)],
      category: categories[Math.floor(Math.random() * categories.length)],
      description: `Test finding ${i}`,
      affectedObjects: [`TestObject${i}`]
    });
  }
  
  return findings;
}
```

## CI/CD Testing Pipeline

### GitHub Actions Testing Workflow
```yaml
name: Comprehensive Testing Pipeline

on:
  pull_request:
    branches: [ main, develop ]
  push:
    branches: [ main, develop ]

jobs:
  powershell-tests:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install Pester
        shell: powershell
        run: Install-Module -Name Pester -Force -SkipPublisherCheck
      - name: Run PowerShell Rule Tests
        shell: powershell
        run: |
          Invoke-Pester -Path "./tests/powershell" -OutputFormat NUnitXml -OutputFile "powershell-test-results.xml"
      - name: Publish PowerShell Test Results
        uses: dorny/test-reporter@v1
        with:
          name: PowerShell Tests
          path: powershell-test-results.xml
          reporter: dotnet-nunit

  desktop-tests:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup .NET
        uses: actions/setup-dotnet@v3
        with:
          dotnet-version: 8.0.x
      - name: Restore dependencies
        run: dotnet restore
      - name: Build
        run: dotnet build --no-restore
      - name: Test
        run: dotnet test --no-build --verbosity normal --collect:"XPlat Code Coverage"
      - name: Upload coverage reports
        uses: codecov/codecov-action@v3

  web-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      - name: Install dependencies
        run: npm ci
      - name: Run unit tests
        run: npm run test:unit
      - name: Run integration tests
        run: npm run test:integration
      - name: Install Playwright Browsers
        run: npx playwright install --with-deps
      - name: Run Playwright E2E Tests
        run: npx playwright test
        env:
          # Use Playwright MCP for debugging failures
          PLAYWRIGHT_MCP_ENABLED: true
      - name: Upload Playwright Report
        uses: actions/upload-artifact@v3
        if: failure()
        with:
          name: playwright-report
          path: playwright-report/

  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run OWASP ZAP Scan
        uses: zaproxy/action-full-scan@v0.4.0
        with:
          target: 'http://localhost:3000'
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
```

## Quality Gates and Metrics

### Test Coverage Requirements
- **PowerShell Rules**: Minimum 90% coverage with Pester
- **Desktop Application**: Minimum 85% code coverage
- **Web Application**: Minimum 80% coverage for components and services
- **API Endpoints**: 100% coverage for critical paths

### Performance Benchmarks
- **Desktop scan execution**: <30 minutes for 10K users/5K computers
- **API response time**: 95th percentile <2 seconds
- **Web dashboard load time**: <3 seconds initial load
- **Real-time updates**: <500ms latency for WebSocket events

### Security Testing Requirements
- **OWASP ZAP**: No high/critical security vulnerabilities
- **Dependency scanning**: No known vulnerabilities in dependencies
- **Static code analysis**: SonarQube quality gate passed
- **Authentication testing**: All auth flows tested and secured

## Debugging and Error Handling

### Playwright MCP Debugging Protocol
When E2E tests fail, the Testing Automation Specialist MUST:
1. Use Playwright MCP to capture detailed error information
2. Analyze browser console logs and network requests
3. Take screenshots and videos of test failures
4. Generate detailed debugging reports with stack traces
5. Coordinate with webapp-coder-expert for issue resolution

### Test Data Management
- **Mock data generation**: Consistent, realistic test datasets
- **Test database setup**: Isolated test environments
- **Data cleanup**: Proper teardown after test execution
- **Cross-environment consistency**: Same test data across all environments

This agent ensures comprehensive quality assurance across all components of the IronVeil platform, with particular emphasis on using Playwright MCP for web application testing and debugging.