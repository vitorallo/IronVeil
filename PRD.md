# Product Requirements Document: IronVeil - MicroSaaS Identity Security Platform

## 1. Introduction

### 1.1 Purpose
This Product Requirements Document (PRD) outlines the features, functionalities, and technical requirements for IronVeil, a **hybrid MicroSaaS Identity Security Platform**. IronVeil combines a lightweight desktop scanner with a powerful cloud-based dashboard to identify and assess identity security misconfigurations and threats within both on-premises Active Directory (AD) and Microsoft Entra ID environments.

The platform enables organizations to proactively address vulnerabilities through **local scanning** and **centralized cloud-based analysis**, providing comprehensive identity attack surface visibility with enterprise-grade features.

### 1.2 Scope & Architecture
IronVeil operates as a **hybrid platform** consisting of:

**Desktop Scanner Component:**
- Lightweight Windows application for local AD/Entra ID scanning
- Minimal UI for backend selection, authentication, and basic results
- PowerShell-based security rule engine
- Secure API communication with cloud backend

**Cloud Backend Platform (ironveil.crimson7.io):**
- Supabase-powered backend with PostgreSQL database
- React/Next.js web dashboard with comprehensive visualization
- Multi-tenant architecture supporting Community and Enterprise editions
- RESTful API for third-party integrations and EASM providers
- Advanced analytics, historical trending, and reporting

The platform will identify Indicators of Exposure (IoEs) and Indicators of Compromise (IoCs) related to identity-based attacks, with enterprise features available immediately rather than as future considerations.

## 2. Platform Features

### 2.1 Desktop Scanner Capabilities

The **IronVeil Desktop Scanner** provides local scanning capabilities with minimal overhead:

**Core Scanning Features:**
- **Backend Selection**: Choose target backend (default: ironveil.crimson7.io)
- **Authentication**: Secure login to cloud platform
- **Local Scanning**: PowerShell-based AD/Entra ID assessment
- **Progress Monitoring**: Real-time scan progress and status updates  
- **Basic Results**: Quick summary of critical findings
- **Cloud Upload**: Automatic JSON submission to selected backend
- **"Open Dashboard"**: Direct browser integration to web platform

**Security Rule Engine:**
- PowerShell-based modular security checks
- Standardized JSON output format for cloud consumption
- Support for custom rule sets and enterprise policies
- Offline capability with cloud synchronization

The comprehensive list of security indicators is detailed in `Identity Security Indicators (checks).md`.

### 2.2 Cloud Platform Features

The **IronVeil Cloud Platform** provides enterprise-grade analysis and visualization:

**Community Edition Features:**
- Web-based dashboard with basic visualizations
- Scan history (last 30 days, up to 10 scans)
- Basic security scorecard and findings list
- PDF report export
- Standard remediation guidance

**Enterprise Edition Features:**
- **Multi-tenant Architecture**: Organization and team management
- **Advanced Analytics**: Historical trending, risk scoring, compliance mapping
- **Custom Dashboards**: Configurable views and KPIs
- **API Access**: RESTful endpoints for third-party integrations
- **EASM Provider Integration**: Standardized connectors for external platforms
- **Advanced Reporting**: Custom reports, executive summaries, compliance exports
- **SSO Integration**: Enterprise authentication (SAML, OIDC)
- **Role-based Access Control**: Granular permissions and audit trails
- **Real-time Monitoring**: Live scan updates and notifications
- **Data Retention**: Unlimited scan history and long-term trending

### 2.3 Security Assessment Coverage

**Active Directory Assessment:**
The desktop scanner performs comprehensive on-premises AD auditing including:
- Weak or misconfigured Access Control Lists (ACLs) and permissions
- Unconstrained and constrained delegation misconfigurations  
- Service Principal Name (SPN) vulnerabilities (Kerberoasting)
- Legacy authentication protocols (NTLM)
- Password policy weaknesses and stale accounts
- Privileged account management issues
- Group Policy Object (GPO) misconfigurations
- LDAP signing requirements and certificate template security
- Built-in operator groups and RC4 encryption support

**Entra ID (Azure AD) Assessment:**
Cloud-specific security indicators including:
- Multi-Factor Authentication (MFA) enforcement gaps
- Application consent and risky API permissions
- Legacy authentication protocol allowances
- Guest account privileges and administrative unit utilization
- Security defaults configuration
- Cross-environment privilege correlation (hybrid identity risks)

**Hybrid Identity Correlation:**
Advanced analysis correlating findings between on-premises AD and Entra ID to identify:
- Accounts privileged in both environments
- Lateral movement vectors between cloud and on-premises
- Identity attack surface bridging

**IoE vs IoC Classification:**
Intelligent differentiation between:
- **Indicators of Exposure (IoEs)**: Risky configurations that can be exploited
- **Indicators of Compromise (IoCs)**: Evidence of ongoing or past compromise

### 2.4 Platform Goals

**Primary Objectives:**
- **Local Scanning**: Secure, on-premises assessment with minimal footprint
- **Centralized Intelligence**: Cloud-based analysis and historical trending  
- **Identity Attack Surface Visibility**: Comprehensive dashboard view
- **Third-party Integration**: RESTful API for EASM providers and security tools
- **Enterprise Scalability**: Multi-tenant architecture from day one
- **Community Access**: Free tier with essential features 

## 3. Reporting and Visualization Architecture

### 3.1 Desktop Scanner Output
The desktop scanner provides **minimal visualization** with focus on efficiency:
- **Quick Summary View**: Critical findings count and overall risk score
- **Progress Indicators**: Real-time scan status and completion percentage  
- **Basic Results Table**: High-level findings with severity indicators
- **"Open Dashboard" Button**: Direct link to full web platform analysis

### 3.2 Cloud Platform Dashboard
The web platform delivers **comprehensive visualization and reporting**:

**Security Scorecard:**
- Overall identity security score with historical trending
- Category breakdown (AD, Entra ID, Privileged Access, Hygiene)
- Risk distribution charts and compliance mapping
- Executive summary with key metrics

**Interactive Dashboard Components:**
- **Real-time Widgets**: Live scan status and recent findings
- **Trend Analysis**: Historical security posture tracking
- **Risk Heatmaps**: Visual representation of critical areas
- **Remediation Progress**: Tracking of addressed issues over time

**Detailed Analysis:**
- **Granular Findings**: Complete vulnerability listings with:
  - Clear issue descriptions and severity categorization
  - Affected entities (users, groups, computers, applications)
  - Prescriptive remediation guidance with step-by-step instructions
  - References to Microsoft documentation and security research
- **Filterable Views**: Sort and filter by severity, category, status
- **Drill-down Capability**: Deep analysis of specific findings

**Export and Integration:**
- **Multiple Formats**: PDF, CSV, JSON exports
- **API Endpoints**: RESTful access for third-party tools
- **EASM Integration**: Standardized connectors for external platforms
- **Custom Reports**: Enterprise edition advanced reporting templates

## 4. Integration Architecture

### 4.1 Desktop Scanner Integrations
**Local Environment Access:**
- **Microsoft Graph API**: Secure Entra ID interaction with OAuth 2.0
- **Active Directory PowerShell Module**: On-premises AD queries
- **System.DirectoryServices**: Direct LDAP connectivity
- **Windows Authentication**: Leveraging current user context

**Cloud Communication:**
- **RESTful API Client**: Secure HTTPS communication with backend
- **JSON Schema Validation**: Standardized data format for cloud upload
- **Authentication Tokens**: JWT-based session management
- **Offline Capability**: Local scan execution with deferred upload

### 4.2 Cloud Platform Integrations
**Third-party API Ecosystem:**
- **RESTful API Gateway**: Standardized endpoints for external access
- **EASM Provider Connectors**: Modular integration framework for:
  - AttackSurface Management platforms
  - Security Information and Event Management (SIEM) systems  
  - Vulnerability Management platforms
  - Risk Assessment tools

**Enterprise Integrations:**
- **Single Sign-On (SSO)**: SAML 2.0, OpenID Connect support
- **Directory Services**: Active Directory, LDAP integration
- **Ticketing Systems**: Jira, ServiceNow webhook integration
- **Notification Systems**: Slack, Teams, email alerts

**Data Exchange Standards:**
- **Standardized JSON Schemas**: Consistent data format for all integrations
- **OpenAPI Specification**: Complete API documentation  
- **Webhook Support**: Real-time event notifications
- **Bulk Export**: CSV, JSON, XML format support

## 5. Business Model & Editions

### 5.1 Community Edition (Free)
**Target**: Small organizations, individual security professionals, students
**Limitations**: 
- Maximum 10 scans per month
- 30-day scan history retention
- Basic web dashboard
- Community support only
- Standard security indicators only

### 5.2 Enterprise Edition (Subscription)
**Target**: Enterprise organizations, MSPs, security consultants
**Features**:
- Unlimited scans and users
- Unlimited scan history and trending
- Advanced analytics and custom dashboards
- API access and third-party integrations
- SSO and enterprise authentication
- Priority support and custom rule development
- White-label options for MSPs

### 5.3 EASM Integration Tier
**Target**: External Attack Surface Management providers
**Features**:
- Full API access with higher rate limits
- Custom integration support
- Webhook notifications and real-time data
- Bulk data export capabilities
- Technical support and documentation

## 6. Security Indicators Implementation

The comprehensive security assessment framework is detailed in `Identity Security Indicators (checks).md`, covering:
- **28+ Tier-based Security Indicators** (Critical, High, Medium, Low Impact)  
- **Active Directory**: 20+ indicators covering delegation, authentication, ACLs, certificates
- **Entra ID**: 12+ indicators covering applications, MFA, guest access, legacy protocols
- **Implementation Priority**: Phased approach starting with critical domain compromise risks


## 7. User Stories

### 7.1 Desktop Scanner User Stories

*   **As an Identity Security Administrator,** I want to install a lightweight desktop scanner so that I can assess my on-premises environment without impacting performance.
*   **As an Identity Security Administrator,** I want to select my preferred backend (community or enterprise) so that I can control where my scan data is processed.
*   **As an Identity Security Administrator,** I want to authenticate securely to the cloud platform so that my scan results are associated with my organization.
*   **As an Identity Security Administrator,** I want to see real-time scan progress so that I know the assessment is running properly.
*   **As an Identity Security Administrator,** I want to see a quick summary of critical findings so that I can immediately understand my highest risks.
*   **As an Identity Security Administrator,** I want a single "Open Dashboard" button so that I can seamlessly access my full analysis in the web platform.

### 7.2 Web Platform User Stories

*   **As an Identity Security Administrator,** I want to view comprehensive dashboards with historical trending so that I can track my security posture improvements over time.
*   **As an Identity Security Administrator,** I want to drill down into specific findings so that I can understand the technical details and remediation steps.
*   **As an Identity Security Administrator,** I want to export reports in multiple formats so that I can share results with stakeholders and integrate with other tools.
*   **As a Security Manager,** I want executive summary dashboards so that I can quickly communicate security posture to leadership.
*   **As a Security Auditor,** I want detailed compliance reports with references so that I can demonstrate adherence to security frameworks.

### 7.3 Enterprise User Stories

*   **As a Security Team Lead,** I want to manage multiple team members and organizations so that I can oversee security assessments across my entire infrastructure.
*   **As an MSP Provider,** I want white-label options so that I can offer identity security assessments under my brand to customers.
*   **As a CISO,** I want API access so that I can integrate identity security data with my existing security tools and dashboards.

### 7.4 EASM Provider User Stories

*   **As an EASM Provider,** I want API access to identity security scan data so that I can incorporate it into my attack surface management platform.
*   **As an EASM Provider,** I want webhook notifications of new scans so that I can provide real-time updates to my customers.
*   **As an EASM Provider,** I want bulk data export capabilities so that I can efficiently process large amounts of identity security data.


## 8. Technical Requirements

### 8.1 Desktop Scanner Requirements

**Performance:**
- Complete comprehensive AD scan (10K users/5K computers) within 30 minutes
- Quick scan of critical indicators within 5 minutes  
- Minimal impact on domain controllers and local machine performance
- Efficient memory usage with streaming data processing

**Compatibility:**
- Windows 10/11 and Windows Server 2016/2019/2022 support
- .NET 8 runtime with minimal dependencies
- PowerShell 5.1+ with Active Directory and Graph modules
- Single executable deployment with embedded dependencies

**Security:**
- Least privilege operation with current user context
- Local data processing with secure cloud transmission
- No persistent storage of sensitive data
- TLS 1.3 encryption for all API communications

### 8.2 Cloud Platform Requirements

**Scalability:**
- Multi-tenant architecture supporting thousands of organizations
- Auto-scaling based on scan volume and user activity
- Real-time processing of scan uploads with queue management
- Global CDN for optimal performance across regions

**Performance:**
- Sub-second API response times for dashboard queries
- Real-time scan status updates via WebSocket connections
- Efficient database queries with proper indexing and caching
- Background processing for heavy analytics and reporting

**Security:**
- Zero-trust architecture with encrypted data at rest and in transit
- JWT-based authentication with refresh token rotation
- Role-based access control (RBAC) with fine-grained permissions
- SOC 2 Type II compliance and regular security audits
- GDPR compliance with data residency options

### 8.3 Technology Stack

**Desktop Scanner:**
- **Framework**: .NET 8 with WPF for minimal UI
- **PowerShell Integration**: System.Management.Automation
- **API Communication**: HttpClient with JSON serialization
- **Authentication**: OAuth 2.0 PKCE flow

**Cloud Backend:**
- **Database**: Supabase (PostgreSQL) with Row Level Security
- **API**: Node.js with NestJS framework
- **Frontend**: React 18 with Next.js 14 and TypeScript
- **Authentication**: Supabase Auth with JWT tokens
- **Hosting**: Vercel for frontend, Railway/Render for backend
- **Monitoring**: Supabase Analytics with custom dashboards

### 8.4 API Architecture

**RESTful Design:**
- OpenAPI 3.0 specification with comprehensive documentation
- Consistent HTTP status codes and error handling
- Rate limiting and API key management for enterprise users
- Webhook support for real-time integrations

**Data Standards:**
- JSON Schema validation for all data exchange
- Standardized error response format
- Consistent naming conventions (camelCase)
- Versioned APIs with backward compatibility

### 8.5 Integration Requirements

**EASM Provider Support:**
- Modular connector architecture for third-party platforms
- Standardized data mapping and transformation layers  
- Bulk export APIs with pagination and filtering
- Real-time webhook notifications for scan events

**Enterprise Integration:**
- SSO support (SAML 2.0, OpenID Connect)
- Directory service integration for user management
- API access with customizable rate limits
- White-label options with custom branding


## 9. Hybrid Architecture Design

### 9.1 Architecture Overview

**Desktop Scanner (Local Component):**
- **Minimal WPF Application**: Simple UI for backend selection, authentication, progress monitoring
- **PowerShell Rule Engine**: Modular security checks with standardized output
- **API Client**: Secure HTTPS communication with cloud backend
- **Local Processing**: All data collection and initial analysis performed locally

**Cloud Platform (SaaS Component):**
- **Supabase Backend**: PostgreSQL database with real-time capabilities  
- **NestJS API**: RESTful endpoints for data ingestion and retrieval
- **Next.js Frontend**: React-based dashboard with comprehensive visualization
- **Multi-tenant Architecture**: Organization-based data isolation

### 9.2 Data Flow Architecture

1. **Local Scanning**: Desktop app executes PowerShell rules against AD/Entra ID
2. **Data Processing**: Results formatted as standardized JSON with security validation
3. **Secure Upload**: TLS 1.3 encrypted transmission to cloud API endpoints
4. **Cloud Storage**: Data stored in Supabase with row-level security
5. **Real-time Analysis**: Background processing for advanced analytics and trending
6. **Dashboard Access**: Web-based visualization with real-time updates

### 9.3 Modular Integration Design

**API-First Approach:**
- OpenAPI 3.0 specification for all endpoints
- Consistent JSON schema for all data exchange
- Versioned APIs with backward compatibility
- Rate limiting and authentication for all access

**EASM Provider Integration:**
- Standardized webhook notifications for scan events
- Bulk data export APIs with filtering and pagination
- Custom connector framework for third-party platforms
- Real-time data streaming for enterprise integrations

### 9.4 Scalability Architecture

**Horizontal Scaling:**
- Stateless API design supporting load balancers
- Database sharding by organization for performance
- CDN integration for global content delivery
- Auto-scaling based on usage patterns

**Performance Optimization:**
- Caching layer for frequently accessed data  
- Background job processing for heavy operations
- Database indexing for optimized query performance
- WebSocket connections for real-time updates

## 10. Future Roadmap & Enhancements

### 10.1 Phase 1: Core Platform (MVP)
- Desktop scanner with basic PowerShell rules
- Community web platform with Supabase
- Basic dashboard and reporting
- API foundation for third-party access

### 10.2 Phase 2: Enterprise Features
- Advanced analytics and trending
- Multi-tenant organization management
- SSO integration and RBAC
- Custom branding and white-label options

### 10.3 Phase 3: Advanced Integrations
- EASM provider ecosystem
- Automated remediation suggestions
- Threat intelligence integration
- Additional identity providers (Okta, Google Workspace)

### 10.4 Phase 4: AI-Powered Enhancements
- Machine learning for anomaly detection
- Behavioral analytics and UEBA integration
- Automated risk scoring optimization
- Natural language report generation

## 11. Success Metrics & KPIs

### 11.1 Technical Metrics
- Desktop scanner installation success rate >95%
- API response times <500ms for 95th percentile
- Platform uptime >99.9% monthly
- Scan completion rate >98% for supported environments

### 11.2 Business Metrics
- Community edition user growth and engagement
- Enterprise conversion rate from community users
- EASM provider integration adoption
- Customer satisfaction scores and retention rates

### 11.3 Security Metrics  
- Vulnerability detection accuracy and false positive rates
- Time to remediation tracking for customer environments
- Compliance framework coverage and reporting
- Security incident reduction correlation

## 12. Conclusion

IronVeil represents a paradigm shift from traditional desktop security tools to a modern, hybrid MicroSaaS platform. By combining the security and performance benefits of local scanning with the power and convenience of cloud-based analytics, IronVeil addresses the evolving needs of identity security professionals.

The hybrid architecture enables organizations to maintain control over their sensitive AD and Entra ID data while benefiting from centralized intelligence, historical trending, and collaborative security management. The platform's API-first design and modular architecture ensure seamless integration with existing security tools and EASM providers.

With immediate enterprise features, multi-tenant capabilities, and a clear path for advanced integrations, IronVeil is positioned to become the leading identity security assessment platform for organizations of all sizes.

## 13. Appendix

### 13.1 References

*   [1] Semperis Blog: 7 Active Directory Misconfigurations to Find and Fix—Now. URL: `https://www.semperis.com/blog/7-active-directory-misconfigurations-to-find-and-fix-now/`
*   [2] HackTheBox Blog: 5 Active Directory misconfigurations (& how they're exploited). URL: `https://www.hackthebox.com/blog/active-directory-misconfigurations`
*   [3] Lepide Blog: Top 10 Active Directory Attack Methods. URL: `https://www.lepide.com/blog/top-10-active-directory-attack-methods/`
*   [4] Microsoft Learn: Best practices for securing Active Directory. URL: `https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory`
*   [5] Semperis Blog: Purple Knight Introduces Entra ID Security Indicators. URL: `https://www.semperis.com/blog/purple-knight-azure-security-indicators/`
*   [6] Microsoft Learn: Best practices to secure with Microsoft Entra ID. URL: `https://learn.microsoft.com/en-us/entra/architecture/secure-best-practices`
*   [7] AppGovScore Blog: Securing Microsoft Entra ID Applications: Addressing the Threat of Misconfigured Permissions. URL: `https://www.appgovscore.com/blog/securing-microsoft-entra-id-applications-addressing-the-threat-of-misconfigured-permissions`
*   [8] Supabase Documentation: Building with Supabase. URL: `https://supabase.com/docs`
*   [9] Next.js Documentation: Building Modern Web Applications. URL: `https://nextjs.org/docs`
*   [10] NestJS Documentation: Scalable Node.js Server Applications. URL: `https://docs.nestjs.com`

### 13.2 Related Documentation
*   **Security Indicators**: See `Identity Security Indicators (checks).md` for comprehensive assessment framework
*   **Implementation Patterns**: See `indicators/implementation-patterns.md` for technical implementation guidance  


