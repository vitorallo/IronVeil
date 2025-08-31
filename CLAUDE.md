# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

IronVeil is a **MicroSaaS Identity Security Platform** that provides hybrid architecture combining a minimal desktop scanner with a full-featured cloud backend. The platform identifies and assesses identity security misconfigurations and threats within both on-premises Active Directory (AD) and Microsoft Entra ID environments, delivering insights through a real-time web dashboard at **ironveil.crimson7.io**.

## Hybrid MicroSaaS Architecture

### System Components

**1. Minimal Desktop Scanner (Windows)**
- **Framework**: .NET 8 WPF with minimal UI
- **PowerShell Engine**: System.Management.Automation for rule execution
- **Authentication**: OAuth 2.0 PKCE for cloud backend access
- **API Client**: Secure upload of scan results to cloud platform
- **Core Function**: Execute PowerShell security rules and upload results

**2. Cloud Backend Platform (ironveil.crimson7.io)**
- **Database**: Supabase (PostgreSQL) with Row Level Security (RLS)
- **Backend API**: NestJS with TypeScript, RESTful endpoints
- **Frontend**: Next.js 14 + React 18 + TailwindCSS + shadcn/ui
- **Authentication**: Supabase Auth with JWT tokens
- **Real-time**: WebSocket subscriptions for live dashboard updates
- **Integration**: EASM provider connectors and third-party APIs

**3. Business Model**
- **Community Edition**: Basic scanning and dashboard (ironveil.crimson7.io)
- **Enterprise Edition**: Advanced analytics, SSO, custom branding
- **EASM Integration**: API access for third-party security platforms

### Technology Stack

**Desktop Application**:
- **.NET 8 WPF**: Minimal scanner interface
- **PowerShell Engine**: System.Management.Automation
- **AD/Entra Integration**: System.DirectoryServices, Microsoft.Graph SDK
- **API Communication**: HttpClient with OAuth 2.0 PKCE

**Cloud Platform**:
- **Database**: Supabase PostgreSQL with RLS policies
- **Backend**: NestJS + TypeScript + Express
- **Frontend**: Next.js 14 + React 18 + TypeScript
- **UI Components**: TailwindCSS + shadcn/ui
- **Real-time**: Supabase subscriptions and WebSocket
- **Authentication**: Supabase Auth with JWT
- **Deployment**: Vercel (frontend), Railway/Render (backend)

### Hybrid Data Flow
1. **Desktop Scanner**: User launches minimal WPF application
2. **Backend Selection**: Choose community (ironveil.crimson7.io) or enterprise backend
3. **Authentication**: OAuth 2.0 PKCE flow to authenticate with cloud platform
4. **Local Scanning**: PowerShell rules execute against AD/Entra ID from `/indicators` folder
5. **Secure Upload**: JSON results uploaded to cloud backend via authenticated API
6. **Real-time Processing**: Backend processes scan data and updates dashboard
7. **Live Dashboard**: Users view comprehensive results through web interface
8. **EASM Integration**: Third-party platforms consume data via RESTful APIs

## Development Structure

### Key Directories
- `/indicators/` - Security check rules and implementation patterns
  - `/pk-reference/` - Reference materials for security checks to be used only by the rule-expert-writer as a learning, do not reuse code from here.
  - `implementation-patterns.md` - Common patterns for security assessments
  - `security-check-pseudocode.md` - Templates for implementing checks
- `PRD.md` - Product Requirements Document
- `Identity Security Indicators (checks).md` - Detailed list of security indicators

### Specialized Agents
The project uses six specialized agents with defined responsibilities:

1. **powershell-security-rules-developer**: Develops PowerShell security check rules in `/indicators` folder with standardized JSON output format for API consumption.

2. **desktop-gui-developer**: Creates minimal WPF scanner with PowerShell engine integration, secure API communication, and OAuth 2.0 PKCE authentication.

3. **supabase-integration-specialist**: Designs database schema, RLS policies, real-time subscriptions, and Supabase authentication. **MUST use Context7 MCP** for latest Supabase documentation.

4. **webapp-coder-expert**: Develops Next.js frontend with real-time dashboard, multi-tenant architecture, and responsive design. **MUST use Context7 MCP** for latest Next.js, React, and TailwindCSS documentation.

5. **api-integration-developer**: Builds NestJS backend with RESTful APIs, EASM provider connectors, webhook systems, and OpenAPI documentation.

6. **testing-automation-specialist**: Creates comprehensive testing framework with E2E, API, and integration tests. **MUST use Playwright MCP** for debugging all test failures.

## Security Implementation Patterns

### Rule-Based Engine
- Security checks follow modular architecture with standardized structure
- Each check has metadata (ID, name, description, severity), parameter validation, LDAP queries, result processing
- Rules are implemented as PowerShell scripts used by the UI
- Common patterns include time-based change detection, attribute-based assessment, inactive object detection

### Risk Scoring
- Weighted risk scoring with severity levels (Critical: 100, High: 75, Medium: 50, Low: 25)
- Contextual modifiers for privileged accounts (1.5x), recent activity (1.25x), public accessibility (1.3x)
- Attack path analysis for privilege escalation, lateral movement, persistence

### Data Processing
- Multi-domain processing with error handling
- Graceful degradation for permission issues
- Progressive data collection with retry logic
- Dynamic threshold calculation based on environment size

## Common Development Tasks

### Development Environment Setup
**Hybrid Development Environment**:

**Desktop Development (Windows 11)**:
- Visual Studio 2022 for .NET 8 WPF development
- PowerShell 7 for rule development and testing
- Git for version control

**Cloud Development**:
- Node.js 18+ for NestJS and Next.js development
- Supabase CLI for local database development
- VS Code with TypeScript, React, and Tailwind extensions
- Docker for local development and testing

**MCP Integration**:
- **Context7 MCP**: For retrieving latest documentation (Supabase, Next.js, React, TailwindCSS)
- **Playwright MCP**: For debugging E2E test failures and browser automation
- **Supabase MCP**: For direct database operations and management

### Build and Development Commands

**Desktop Application (.NET 8)**:
- `dotnet build` - Build WPF application
- `dotnet test` - Run unit tests
- `dotnet run` - Run desktop scanner for debugging
- `dotnet publish -r win-x64 --self-contained --single-file` - Create executable

**Cloud Backend (NestJS + Supabase)**:
- `npm run dev` - Start NestJS development server
- `npm run build` - Build production backend
- `npm test` - Run API tests
- `supabase start` - Start local Supabase instance
- `supabase db push` - Apply database migrations
- `supabase gen types typescript` - Generate TypeScript types

**Frontend (Next.js)**:
- `npm run dev` - Start Next.js development server
- `npm run build` - Build production frontend
- `npm run test` - Run React component tests
- `npm run test:e2e` - Run Playwright E2E tests

**PowerShell Rules**:
- `Test-SecurityRule -RuleName "RuleName"` - Test individual rules
- `Invoke-Pester` - Run PowerShell test framework

### Debugging and Development
**Visual Studio 2022 Setup:**
- Enable debugging for both C# and PowerShell components
- Set breakpoints in C# rule engine and PowerShell execution
- Use Immediate Window for testing LDAP queries and Graph API calls
- Configure solution for mixed-mode debugging when needed

**PowerShell Development:**
- Use PowerShell ISE or VS Code PowerShell extension
- Test rules individually before integration
- Use `Write-Debug` and `Write-Verbose` for rule debugging
- Validate LDAP query syntax with real AD environment

### Agent Collaboration Workflow

**Phase 1: Backend Foundation**
1. **supabase-integration-specialist**: Create database schema with RLS policies
2. **api-integration-developer**: Build NestJS API with authentication
3. **webapp-coder-expert**: Develop Next.js dashboard with real-time updates

**Phase 2: Desktop Integration** 
4. **desktop-gui-developer**: Create minimal WPF scanner with API integration
5. **powershell-security-rules-developer**: Develop standardized security rules
6. **testing-automation-specialist**: Create comprehensive test coverage

**Integration Checkpoints**:
- Backend API can receive and process scan uploads
- Desktop scanner authenticates and uploads successfully 
- PowerShell rules output standardized JSON format
- Real-time dashboard updates from scan results
- End-to-end workflow: scan → upload → dashboard → insights

### Phase Completion Procedures

**MANDATORY: At the completion of every phase, you MUST perform these tasks:**

1. **Update TASKS.md Phase Status**:
   - Mark completed phase with ✅ COMPLETED status
   - Add completion metadata: date, duration, report location
   - Update next phase to 🚀 IN EXECUTION or ⏳ PENDING as appropriate
   - Update Integration Checkpoints section to reflect current progress

2. **Create Phase Completion Report**:
   - Generate comprehensive `PHASE{N}-COMPLETION-SUMMARY.md` report
   - Include: objectives achieved, technical implementation details, success metrics
   - Document integration points available for next phases
   - Provide reproduction commands and local development access

3. **Organize Development Documentation**:
   - Move completion report to `/development_reports/` directory
   - Update TASKS.md references to point to new report location
   - Ensure `/development_reports/` directory exists before moving files

**Example Phase Completion Updates for TASKS.md**:
```markdown
## Phase N: Phase Name ✅ COMPLETED
**🖥️ Development Environment**: Environment Type
**Completed**: Date | **Duration**: Time | **Report**: `/development_reports/PHASEN-COMPLETION-SUMMARY.md`

### N.1 Subsection Name **[agent-name]** ✅
- [x] Completed task 1
- [x] Completed task 2

## Phase N+1: Next Phase Name 🚀 IN EXECUTION  
**🖥️ Development Environment**: Environment Type
**Started**: Date | **Status**: In progress description

### N+1.1 Subsection Name **[agent-name]** 🚀 IN PROGRESS
- [ ] Pending task 1
- [ ] Pending task 2
```

**Integration Checkpoints Updates**:
```markdown
### Integration Checkpoints
- **Phase N**: ✅ Brief description of what was completed
- **Phase N+1**: 🚀 Brief description of what's in progress (IN PROGRESS)
- **Phase N+2**: Brief description of what's pending
```

This systematic approach ensures consistent project tracking and clear visibility into development progress across all phases.

### Integration Requirements

#### PowerShell Rule Specifications
PowerShell rules must adhere to these standards for C# integration:

**Required Metadata Format:**
```powershell
# Rule metadata (at top of each .ps1 file)
<#
.SYNOPSIS
Brief rule description

.METADATA
{
  "id": "unique-rule-identifier",
  "name": "Human Readable Name", 
  "description": "Detailed explanation",
  "category": "security_category",
  "severity": "Critical|High|Medium|Low",
  "weight": 8,
  "impact": 9,
  "frameworks": ["MITRE", "NIST"],
  "targets": ["ActiveDirectory", "EntraID"]
}
#>
```

**Required JSON Output Format for Cloud API:**
```powershell
# Rules must return JSON-serializable objects for API upload
return @{
    CheckId = "rule-identifier"
    Timestamp = (Get-Date).ToString("o")  # ISO 8601 format
    Status = "Success|Failed|Error"  
    Score = 75
    Severity = "Critical|High|Medium|Low"
    Category = "PrivilegedAccess|Authentication|Authorization"
    Findings = @(
        @{
            ObjectName = "affected-object"
            ObjectType = "User|Group|Computer|Application"
            RiskLevel = "High"
            Description = "issue description" 
            Remediation = "fix instructions"
            AffectedAttributes = @("userAccountControl", "memberOf")
        }
    )
    Message = "Summary message"
    AffectedObjects = 5
    IgnoredObjects = 2
    Metadata = @{
        Domain = "contoso.com"
        TenantId = "guid-if-entra-id"
        ExecutionTime = 1.5  # seconds
    }
}
```

**Error Handling Requirements:**
- Consistent try/catch blocks with JSON-serializable error objects
- Graceful degradation for permission issues with detailed logging
- Timeout handling for long-running queries (max 30 seconds per rule)
- Network error handling for cloud API communication
- All security rules must be testable independently and through desktop application
- API error responses must include correlation IDs for debugging

## MCP Integration Requirements

**Context7 MCP Usage (MANDATORY):**
- **supabase-integration-specialist**: Must use Context7 MCP for latest Supabase features, RLS policies, real-time subscriptions
- **webapp-coder-expert**: Must use Context7 MCP for Next.js 14, React 18, TailwindCSS, shadcn/ui documentation

**Playwright MCP Usage (MANDATORY):**
- **testing-automation-specialist**: Must use Playwright MCP for debugging all E2E test failures, browser automation issues

## Development Guidelines

**Hybrid Architecture Focus:**
- Desktop application: Minimal UI, secure API integration, PowerShell engine
- Cloud platform: Full-featured dashboard, real-time updates, multi-tenant architecture
- API-first design: Enable EASM provider integrations and third-party platforms
- Security: Multi-tenant data isolation, secure authentication, encrypted communication

**PowerShell Rules:**
- Develop in `/indicators` folder with standardized JSON output
- Follow implementation patterns for consistent structure
- Ensure rules work with both desktop execution and cloud processing
- All output must be JSON-serializable for API consumption

**Quality Standards:**
- Real-time dashboard updates within 5 seconds of scan completion
- Multi-tenant data isolation using Supabase RLS policies
- Comprehensive E2E testing with Playwright MCP debugging
- API documentation with OpenAPI 3.0 specifications

## MicroSaaS Platform Goals

**Primary Objectives:**
- **Hybrid Architecture**: Minimal desktop scanner + full cloud backend
- **Real-time Insights**: Live dashboard with WebSocket updates at ironveil.crimson7.io
- **Multi-tenant SaaS**: Community, Enterprise, and EASM integration tiers
- **API-first Design**: Enable third-party EASM provider integrations
- **Comprehensive Coverage**: Both AD and Entra ID security assessment

**Business Model:**
- **Community**: Basic scanning and dashboard access
- **Enterprise**: Advanced analytics, SSO, custom branding, multi-user
- **EASM Integration**: API access for security platforms and service providers

**Technical Excellence:**
- Real-time dashboard updates using Supabase subscriptions
- Secure multi-tenant architecture with Row Level Security
- Comprehensive API documentation for partner integrations
- Modern tech stack with TypeScript, React, and cloud-native deployment