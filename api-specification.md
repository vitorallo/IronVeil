# IronVeil API Specification

## Overview

The IronVeil API provides comprehensive access to identity security scanning capabilities, multi-tenant organization management, and real-time dashboard data. This RESTful API follows OpenAPI 3.0 specifications and supports both desktop scanner integration and third-party EASM provider connectivity.

**Base URL**: `https://api.ironveil.crimson7.io`  
**API Version**: v1  
**Authentication**: JWT Bearer tokens and API keys

## Authentication

### JWT Authentication (Users)
Used by web application and desktop scanner for user-specific operations.

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### API Key Authentication (EASM Providers)
Used by third-party integrations for bulk data access.

```http
X-API-Key: ak_live_1234567890abcdef...
```

## Core API Endpoints

### Desktop Scanner Integration

#### Upload Scan Results
Upload scan results from desktop application to cloud backend.

```http
POST /api/v1/scans
Authorization: Bearer {jwt_token}
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "Weekly Security Scan - Marketing Domain",
  "scanType": "hybrid",
  "scanData": {
    "findings": [
      {
        "checkId": "privileged-group-membership",
        "timestamp": "2024-01-15T10:30:00Z",
        "status": "Success",
        "score": 75,
        "severity": "High",
        "category": "PrivilegedAccess",
        "findings": [
          {
            "objectName": "john.doe",
            "objectType": "User",
            "riskLevel": "High",
            "description": "User has been member of Domain Admins for 180+ days without recent activity",
            "remediation": "Review and remove unnecessary administrative privileges",
            "affectedAttributes": ["memberOf", "lastLogon"]
          }
        ],
        "message": "Found 3 users with excessive privileges",
        "affectedObjects": 3,
        "ignoredObjects": 0,
        "metadata": {
          "domain": "marketing.contoso.com",
          "tenantId": "12345678-1234-1234-1234-123456789abc",
          "executionTime": 2.5
        }
      }
    ],
    "overallScore": 68,
    "execution": {
      "startTime": "2024-01-15T10:25:00Z",
      "endTime": "2024-01-15T10:35:00Z",
      "rulesExecuted": [
        "privileged-group-membership",
        "stale-accounts",
        "unconstrained-delegation"
      ],
      "environment": {
        "adDomains": ["contoso.com", "marketing.contoso.com"],
        "entraIdTenant": "contoso.onmicrosoft.com"
      }
    }
  },
  "metadata": {
    "scannerVersion": "1.0.0",
    "computerName": "DESKTOP-SCANNER01",
    "userName": "scanner-service"
  }
}
```

**Response:**
```json
{
  "scanId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "processing",
  "message": "Scan uploaded successfully and is being processed",
  "estimatedCompletionTime": "2024-01-15T10:37:00Z",
  "dashboardUrl": "https://ironveil.crimson7.io/dashboard/scans/550e8400-e29b-41d4-a716-446655440000"
}
```

#### Check Scan Status
Monitor processing status of uploaded scans.

```http
GET /api/v1/scans/{scanId}/status
Authorization: Bearer {jwt_token}
```

**Response:**
```json
{
  "scanId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "progress": 100,
  "message": "Scan processing completed successfully",
  "completedAt": "2024-01-15T10:36:45Z",
  "results": {
    "totalFindings": 15,
    "criticalFindings": 2,
    "highFindings": 5,
    "mediumFindings": 6,
    "lowFindings": 2,
    "overallScore": 68
  }
}
```

#### Retrieve Detailed Results
Get comprehensive scan results for dashboard display.

```http
GET /api/v1/scans/{scanId}/results
Authorization: Bearer {jwt_token}
```

**Response:**
```json
{
  "scanId": "550e8400-e29b-41d4-a716-446655440000",
  "organizationId": "org_123abc",
  "name": "Weekly Security Scan - Marketing Domain",
  "completedAt": "2024-01-15T10:36:45Z",
  "overallScore": 68,
  "riskLevel": "medium",
  "findings": [
    {
      "id": "finding_001",
      "ruleId": "privileged-group-membership",
      "ruleName": "Privileged Group Membership Analysis",
      "category": "PrivilegedAccess",
      "severity": "high",
      "title": "Users with Excessive Administrative Privileges",
      "description": "Multiple users have been members of privileged groups for extended periods",
      "affectedObjects": [
        {
          "name": "john.doe",
          "type": "User",
          "domain": "marketing.contoso.com",
          "lastActivity": "2024-01-10T14:30:00Z"
        }
      ],
      "remediation": "Review administrative group memberships and implement Just-In-Time access",
      "riskScore": 85,
      "status": "open"
    }
  ],
  "summary": {
    "totalFindings": 15,
    "findingsByCategory": {
      "PrivilegedAccess": 5,
      "Authentication": 4,
      "Authorization": 3,
      "Configuration": 3
    },
    "affectedDomains": ["contoso.com", "marketing.contoso.com"],
    "scanDuration": "10m 45s"
  }
}
```

### Organization Management

#### Get Organization Summary
Retrieve high-level security metrics for organization dashboard.

```http
GET /api/v1/organizations/{orgId}/summary
Authorization: Bearer {jwt_token}
```

**Response:**
```json
{
  "organizationId": "org_123abc",
  "name": "Contoso Corporation",
  "tier": "enterprise",
  "securityScore": 72,
  "lastScanDate": "2024-01-15T10:36:45Z",
  "metrics": {
    "totalScans": 156,
    "scansThisMonth": 12,
    "criticalFindings": 8,
    "highFindings": 23,
    "resolvedFindings": 89,
    "averageResolutionTime": "4.2 days"
  },
  "trends": {
    "scoreChange": "+5",
    "findingsTrend": "-12%",
    "lastPeriod": "30 days"
  },
  "compliance": {
    "frameworks": ["NIST", "ISO27001"],
    "overallCompliance": 78,
    "criticalGaps": 3
  }
}
```

### EASM Provider Integration

#### Bulk Export Scans
Export scan data for EASM providers with pagination and filtering.

```http
GET /api/v1/integrations/scans?limit=100&offset=0&since=2024-01-01T00:00:00Z
X-API-Key: ak_live_1234567890abcdef...
```

**Query Parameters:**
- `limit`: Maximum number of results (default: 100, max: 1000)
- `offset`: Pagination offset (default: 0)
- `since`: Only return scans after this timestamp (ISO 8601)
- `organizationIds[]`: Filter by specific organization IDs
- `severity[]`: Filter by finding severity levels
- `status[]`: Filter by scan status

**Response:**
```json
{
  "data": [
    {
      "scanId": "550e8400-e29b-41d4-a716-446655440000",
      "organizationId": "org_123abc",
      "organizationName": "Contoso Corporation",
      "timestamp": "2024-01-15T10:36:45Z",
      "findings": [
        {
          "id": "finding_001",
          "severity": "high",
          "category": "PrivilegedAccess",
          "description": "Users with excessive administrative privileges detected",
          "affectedAssets": ["john.doe", "jane.smith"],
          "riskScore": 85,
          "domain": "contoso.com"
        }
      ],
      "securityScore": 68,
      "riskLevel": "medium",
      "metadata": {
        "scanType": "hybrid",
        "rulesExecuted": 15,
        "executionTime": 645,
        "environment": {
          "adDomains": ["contoso.com", "marketing.contoso.com"],
          "entraIdTenant": "contoso.onmicrosoft.com"
        }
      }
    }
  ],
  "pagination": {
    "limit": 100,
    "offset": 0,
    "total": 1247,
    "hasMore": true,
    "nextOffset": 100
  },
  "meta": {
    "requestId": "req_987654321",
    "timestamp": "2024-01-16T09:15:30Z",
    "apiVersion": "v1"
  }
}
```

#### Organization Security Summary
Get condensed security overview for EASM provider consumption.

```http
GET /api/v1/integrations/organizations/{orgId}/summary
X-API-Key: ak_live_1234567890abcdef...
```

**Response:**
```json
{
  "organizationId": "org_123abc",
  "organizationName": "Contoso Corporation",
  "lastAssessment": "2024-01-15T10:36:45Z",
  "securityScore": 68,
  "riskLevel": "medium",
  "exposedAssets": [
    {
      "type": "User",
      "name": "service.account",
      "risk": "high",
      "issues": ["unconstrained-delegation", "never-expires-password"]
    },
    {
      "type": "Computer",
      "name": "OLD-DC01",
      "risk": "medium", 
      "issues": ["inactive-dc", "outdated-os"]
    }
  ],
  "criticalFindings": 8,
  "totalFindings": 45,
  "domains": ["contoso.com", "marketing.contoso.com"],
  "lastScanId": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Webhook Management

#### Register Webhook
Register endpoint for real-time event notifications.

```http
POST /api/v1/webhooks/register
Authorization: Bearer {jwt_token}
Content-Type: application/json
```

**Request Body:**
```json
{
  "url": "https://your-easm-platform.com/webhooks/ironveil",
  "events": [
    "scan.completed",
    "finding.created",
    "finding.resolved",
    "organization.updated"
  ],
  "description": "ACME EASM Platform Integration",
  "secret": "webhook_secret_key_for_signature_validation"
}
```

**Response:**
```json
{
  "webhookId": "webhook_456def",
  "status": "active",
  "createdAt": "2024-01-16T09:20:00Z",
  "nextTestAt": "2024-01-16T09:25:00Z"
}
```

#### Test Webhook
Send test event to validate webhook endpoint.

```http
POST /api/v1/webhooks/{webhookId}/test
Authorization: Bearer {jwt_token}
```

**Response:**
```json
{
  "testId": "test_789ghi",
  "status": "success",
  "responseTime": 245,
  "statusCode": 200,
  "message": "Webhook endpoint responded successfully"
}
```

## WebSocket Events (Real-time Updates)

### Scan Progress Updates
Real-time scan processing status for dashboard.

```javascript
// Connect to WebSocket
const ws = new WebSocket('wss://api.ironveil.crimson7.io/ws');

// Authenticate
ws.send(JSON.stringify({
  type: 'auth',
  token: 'your_jwt_token'
}));

// Subscribe to scan updates
ws.send(JSON.stringify({
  type: 'subscribe',
  channel: 'scan_updates',
  organizationId: 'org_123abc'
}));

// Receive updates
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  if (data.type === 'scan_update') {
    console.log('Scan progress:', data.payload);
    // {
    //   scanId: "550e8400-e29b-41d4-a716-446655440000",
    //   status: "processing",
    //   progress: 65,
    //   currentRule: "stale-accounts",
    //   estimatedCompletion: "2024-01-15T10:37:00Z"
    // }
  }
};
```

### Dashboard Metrics Updates
Live updates for dashboard widgets and charts.

```javascript
// Subscribe to metrics updates
ws.send(JSON.stringify({
  type: 'subscribe',
  channel: 'metrics_updates',
  organizationId: 'org_123abc'
}));

// Receive real-time metrics
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  if (data.type === 'metrics_update') {
    console.log('New metrics:', data.payload);
    // {
    //   type: "scan_completed",
    //   organizationId: "org_123abc",
    //   securityScore: 68,
    //   newFindings: 5,
    //   resolvedFindings: 2,
    //   timestamp: "2024-01-15T10:36:45Z"
    // }
  }
};
```

## Error Handling

### Error Response Format
All API errors follow consistent structure with correlation IDs.

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": [
      {
        "field": "scanData.findings[0].severity",
        "message": "Must be one of: critical, high, medium, low"
      }
    ],
    "correlationId": "corr_abc123def456",
    "timestamp": "2024-01-16T09:30:00Z",
    "documentation": "https://docs.ironveil.crimson7.io/api/errors#validation_error"
  }
}
```

### HTTP Status Codes

- **200 OK**: Successful request
- **201 Created**: Resource created successfully
- **400 Bad Request**: Invalid request format or parameters
- **401 Unauthorized**: Missing or invalid authentication
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource does not exist
- **409 Conflict**: Resource already exists or conflict
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Server error
- **503 Service Unavailable**: Temporary service unavailability

## Rate Limiting

### User Authentication (JWT)
- **Standard requests**: 1000 requests per hour
- **Scan uploads**: 50 uploads per hour
- **WebSocket connections**: 10 concurrent connections

### API Key Authentication (EASM)
- **Bulk exports**: 100 requests per hour
- **Organization summaries**: 500 requests per hour
- **Webhook management**: 100 requests per hour

Rate limit headers included in all responses:
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 985
X-RateLimit-Reset: 1642320000
```

## Data Models

### Scan Result Schema
Complete data model for scan results and findings.

```json
{
  "scanId": "string (UUID)",
  "organizationId": "string",
  "userId": "string (UUID)",
  "name": "string",
  "description": "string (optional)",
  "scanType": "ad_only | entra_only | hybrid | custom",
  "status": "pending | processing | completed | failed | cancelled",
  "overallScore": "integer (0-100)",
  "riskLevel": "critical | high | medium | low | info",
  "findings": [
    {
      "id": "string (UUID)",
      "ruleId": "string",
      "ruleName": "string", 
      "category": "string",
      "severity": "critical | high | medium | low",
      "title": "string",
      "description": "string",
      "affectedObjects": [
        {
          "name": "string",
          "type": "User | Group | Computer | Application",
          "domain": "string",
          "attributes": "object"
        }
      ],
      "remediation": "string",
      "references": ["string"],
      "riskScore": "integer (0-100)",
      "status": "open | in_progress | resolved | false_positive | accepted_risk",
      "createdAt": "string (ISO 8601)",
      "updatedAt": "string (ISO 8601)"
    }
  ],
  "metadata": {
    "scannerVersion": "string",
    "rulesExecuted": ["string"],
    "executionTime": "number (seconds)",
    "environment": {
      "adDomains": ["string"],
      "entraIdTenant": "string"
    }
  },
  "startedAt": "string (ISO 8601)",
  "completedAt": "string (ISO 8601)",
  "createdAt": "string (ISO 8601)",
  "updatedAt": "string (ISO 8601)"
}
```

### Organization Schema
Multi-tenant organization data model.

```json
{
  "id": "string (UUID)",
  "name": "string",
  "slug": "string (unique)",
  "tier": "community | enterprise | easm",
  "settings": {
    "scanFrequency": "string",
    "retentionPeriod": "string",
    "alertThresholds": "object"
  },
  "subscriptionData": {
    "planId": "string",
    "billingCycle": "string",
    "nextBillingDate": "string (ISO 8601)"
  },
  "createdAt": "string (ISO 8601)",
  "updatedAt": "string (ISO 8601)"
}
```

## Integration Examples

### Desktop Scanner Authentication Flow
Complete OAuth 2.0 PKCE implementation for desktop application.

```csharp
// C# Desktop Scanner Authentication
public class IronVeilAuthenticator 
{
    private const string AuthUrl = "https://auth.ironveil.crimson7.io";
    private const string ClientId = "desktop_scanner_client";
    
    public async Task<string> AuthenticateAsync()
    {
        // Generate PKCE parameters
        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        
        // Build authorization URL
        var authUrl = $"{AuthUrl}/authorize" +
                     $"?client_id={ClientId}" +
                     $"&redirect_uri=http://localhost:8080/callback" +
                     $"&response_type=code" +
                     $"&scope=scan:upload scan:read" +
                     $"&code_challenge={codeChallenge}" +
                     $"&code_challenge_method=S256";
        
        // Open browser and wait for callback
        Process.Start(new ProcessStartInfo(authUrl) { UseShellExecute = true });
        var authCode = await ListenForCallback();
        
        // Exchange code for tokens
        var tokenResponse = await ExchangeCodeForTokens(authCode, codeVerifier);
        return tokenResponse.AccessToken;
    }
}
```

### EASM Provider Integration
Example connector implementation for third-party EASM platforms.

```typescript
// TypeScript EASM Connector Example
export class IronVeilConnector {
    private apiKey: string;
    private baseUrl = 'https://api.ironveil.crimson7.io';
    
    constructor(apiKey: string) {
        this.apiKey = apiKey;
    }
    
    async exportOrganizationData(orgId: string): Promise<SecuritySummary> {
        const response = await fetch(
            `${this.baseUrl}/api/v1/integrations/organizations/${orgId}/summary`,
            {
                headers: {
                    'X-API-Key': this.apiKey,
                    'Accept': 'application/json'
                }
            }
        );
        
        if (!response.ok) {
            throw new Error(`API Error: ${response.status} ${response.statusText}`);
        }
        
        return await response.json();
    }
    
    async setupWebhook(url: string, events: string[]): Promise<WebhookResult> {
        const response = await fetch(`${this.baseUrl}/api/v1/webhooks/register`, {
            method: 'POST',
            headers: {
                'X-API-Key': this.apiKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url, events })
        });
        
        return await response.json();
    }
}
```

## Security Considerations

### API Security
- **TLS 1.3**: All communications encrypted in transit
- **JWT Tokens**: Short-lived access tokens with refresh capabilities
- **API Key Management**: Secure key generation with prefix identification
- **Rate Limiting**: Protect against abuse and DDoS attacks
- **Input Validation**: Comprehensive request validation and sanitization

### Data Privacy
- **Multi-tenant Isolation**: Row Level Security policies enforce data separation
- **GDPR Compliance**: Support for data export and deletion requests
- **Audit Logging**: Comprehensive access and modification tracking
- **Data Retention**: Configurable retention policies per organization tier

### Authentication Security
- **OAuth 2.0 PKCE**: Secure authentication for desktop applications
- **JWT Best Practices**: Proper token validation and expiration handling
- **Scope-based Authorization**: Fine-grained permissions for different operations
- **Webhook Signatures**: HMAC validation for webhook event authenticity

## Development and Testing

### OpenAPI Specification
Complete OpenAPI 3.0 specification available at:
```
https://api.ironveil.crimson7.io/api-docs
```

### Postman Collection
Pre-configured Postman collection with authentication and example requests:
```
https://docs.ironveil.crimson7.io/postman/collection.json
```

### SDK Libraries
Official SDKs available for:
- **TypeScript/JavaScript**: `npm install @ironveil/sdk`
- **C#/.NET**: `dotnet add package IronVeil.SDK`
- **Python**: `pip install ironveil-sdk`

### Testing Environment
Sandbox environment for testing integrations:
```
Base URL: https://api.sandbox.ironveil.crimson7.io
```

Test API keys and organizations available for development and integration testing.