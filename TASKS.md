# Desktop Application Development Tasks - IronVeil

## Phase 1: Project Foundation & Setup

### 1.1 Project Structure & Solution Setup **[desktop-gui-developer]**
- [ ] Create .NET 8 solution with WPF application project
- [ ] Set up project structure following the architecture defined in CLAUDE.md
- [ ] Configure NuGet packages:
  - System.DirectoryServices (AD integration)
  - Microsoft.Graph SDK (Entra ID integration)
  - System.Management.Automation (PowerShell integration)
  - QuestPDF (PDF reporting)
  - OxyPlot or LiveCharts (dashboard visualizations)
  - System.CommandLine (CLI support)
- [ ] Create core folder structure matching architectural components
- [ ] Set up build configuration for single-file executable publishing

### 1.2 Core Infrastructure **[desktop-gui-developer]**
- [ ] Implement base classes for security checks following patterns in `/indicators/implementation-patterns.md`
- [ ] Create LDAP connection and query utilities
- [ ] Implement Microsoft Graph API authentication and query framework
- [ ] Create result object models (CheckResult, CheckMetadata, RiskItem, etc.)
- [ ] Implement risk scoring algorithms from implementation patterns
- [ ] Create error handling and resilience patterns
- [ ] **Integration Checkpoint**: Establish PowerShell rule execution framework using System.Management.Automation

## Phase 2: Data Collection Modules

### 2.1 Active Directory Collector **[desktop-gui-developer]**
- [ ] Implement LDAP query builder with common filter patterns
- [ ] Create domain enumeration and availability checking
- [ ] Implement privilege group detection utilities
- [ ] Create time-based filtering for change detection
- [ ] Implement bitwise attribute filtering for UserAccountControl flags
- [ ] Add metadata processing for attribute change tracking
- [ ] Create PowerShell cmdlet integration wrapper

### 2.2 Entra ID Collector **[desktop-gui-developer]**
- [ ] Implement Microsoft Graph API authentication (OAuth 2.0, service principal)
- [ ] Create Graph API query utilities for users, groups, applications
- [ ] Implement Conditional Access policy enumeration
- [ ] Add service principal and app registration analysis
- [ ] Create tenant configuration assessment utilities
- [ ] Implement guest user and external identity analysis

### 2.3 Configuration Management **[desktop-gui-developer]**
- [ ] Create ignore list processing functionality
- [ ] Implement dynamic threshold calculation
- [ ] Add environment size detection and scaling
- [ ] Create domain-specific configuration handling

## Phase 3: Security Analysis Engine

### 3.1 Rule Engine Foundation **[desktop-gui-developer]**
- [ ] Create rule loader that reads PowerShell scripts from `/indicators` folder
- [ ] Implement rule execution engine with sandbox
- [ ] Create rule metadata parser and validator
- [ ] Implement result aggregation and correlation
- [ ] Add rule dependency management
- [ ] **Integration Checkpoint**: Test PowerShell rule execution and result parsing

### 3.2 Core Security Checks **[powershell-security-rules-developer + desktop-gui-developer]**
**PowerShell Rules Development (Priority Order):**
- [ ] Privileged group membership changes detection
- [ ] Unconstrained Kerberos delegation assessment
- [ ] Protocol transition delegation detection
- [ ] Inactive domain controller identification
- [ ] Stale account detection (users and computers)
- [ ] Dangerous UserAccountControl flags assessment
- [ ] AdminSDHolder and delegation permission analysis
- [ ] Kerberos encryption type assessment (RC4 usage)
- [ ] LDAP signing requirement validation
- [ ] Certificate template security evaluation

**Integration Tasks:**
- [ ] **Integration Checkpoint**: Validate each rule works with C# rule engine
- [ ] **Testing**: Ensure rule metadata is properly parsed by desktop application
- [ ] **Testing**: Verify rule results integrate with report generation

### 3.3 Entra ID Specific Checks **[powershell-security-rules-developer + desktop-gui-developer]**
**PowerShell Rules Development:**
- [ ] MFA enforcement for privileged accounts
- [ ] Application consent and permission assessment
- [ ] Legacy authentication protocol detection
- [ ] Guest user privilege analysis
- [ ] Security defaults validation
- [ ] Administrative unit utilization
- [ ] Hybrid identity correlation checks

**Integration Tasks:**
- [ ] **Integration Checkpoint**: Test Entra ID rules with Graph API integration
- [ ] **Testing**: Validate hybrid identity correlation between AD and Entra ID rules

### 3.4 Risk Assessment & Correlation **[desktop-gui-developer]**
- [ ] Implement weighted risk scoring algorithm
- [ ] Create attack path analysis engine
- [ ] Add hybrid identity risk correlation
- [ ] Implement IoE vs IoC classification
- [ ] Create trend analysis foundation
- [ ] **Integration Checkpoint**: Ensure risk scoring works with PowerShell rule results

## Phase 4: User Interface Development

### 4.1 Main Application Window (WPF) **[desktop-gui-developer]**
- [ ] Design and implement main window layout
- [ ] Create scan configuration interface (AD, Entra ID, both)
- [ ] Implement progress indication during scans
- [ ] Add real-time status updates and logging
- [ ] Create simple authentication setup for Entra ID
- [ ] **Integration Checkpoint**: UI displays PowerShell rule execution status and results

### 4.2 Dashboard & Results Display **[desktop-gui-developer]**
- [ ] Design security scorecard visualization
- [ ] Implement risk level summary charts
- [ ] Create detailed findings list with filtering/sorting
- [ ] Add remediation guidance display panels
- [ ] Implement drill-down capability for detailed analysis
- [ ] Create trend visualization (basic foundation)
- [ ] **Integration Checkpoint**: Dashboard displays results from PowerShell security rules

### 4.3 Settings & Configuration **[desktop-gui-developer]**
- [ ] Create application settings management
- [ ] Implement scan frequency and scope configuration
- [ ] Add ignore list management interface
- [ ] Create export format preferences
- [ ] Add logging and diagnostic configuration
- [ ] Add rule selection/configuration interface for PowerShell rules

## Phase 5: Reporting & Export

### 5.1 Report Generation **[desktop-gui-developer]**
- [ ] Implement JSON export for partner integration
- [ ] Create PDF report generation using QuestPDF
- [ ] Add CSV export for spreadsheet analysis
- [ ] Implement HTML dashboard export
- [ ] Create structured report templates
- [ ] **Integration Checkpoint**: Reports include results from all PowerShell security rules

### 5.2 Report Content **[desktop-gui-developer]**
- [ ] Design executive summary format
- [ ] Implement detailed findings with remediation steps
- [ ] Add severity-based prioritization
- [ ] Create affected entities listing
- [ ] Include references and citations
- [ ] Add compliance mapping (future consideration)
- [ ] **Testing**: Verify report content reflects PowerShell rule findings and metadata

## Phase 6: CLI & Automation Support

### 6.1 Command Line Interface **[desktop-gui-developer]**
- [ ] Implement headless execution mode
- [ ] Create command-line parameter parsing
- [ ] Add JSON-only output mode for automation
- [ ] Implement batch scanning capabilities
- [ ] Create configuration file support
- [ ] **Integration Checkpoint**: CLI can execute all PowerShell rules and generate reports

### 6.2 Integration Preparation **[desktop-gui-developer]**
- [ ] Design API endpoint specifications (for future web app)
- [ ] Create data models for external consumption
- [ ] Implement client identification for partner matching
- [ ] Add scan metadata for tracking and correlation

## Phase 7: Testing & Validation

### 7.1 Unit Testing **[desktop-gui-developer + powershell-security-rules-developer]**
**C# Application Testing:**
- [ ] Create test framework for security check modules
- [ ] Implement mock AD/Graph data providers
- [ ] Test risk scoring algorithms
- [ ] Validate LDAP query generation
- [ ] Test error handling and resilience patterns

**PowerShell Rule Testing:**
- [ ] Create PowerShell test framework for individual rules
- [ ] Test rule execution in isolation
- [ ] Validate rule metadata parsing
- [ ] Test rule error handling

### 7.2 Integration Testing **[desktop-gui-developer]**
- [ ] Test PowerShell rule execution through C# application
- [ ] Test against various AD environments (different versions, sizes)
- [ ] Validate Entra ID tenant variations
- [ ] Test hybrid environment scenarios
- [ ] Validate report generation across different data sets
- [ ] Performance testing with large environments
- [ ] **Integration Checkpoint**: End-to-end testing with all PowerShell rules

### 7.3 Security Testing **[desktop-gui-developer]**
- [ ] Validate least privilege operation
- [ ] Test credential handling and storage
- [ ] Validate data encryption in transit and at rest
- [ ] Test against malicious input scenarios
- [ ] Audit logging and compliance verification
- [ ] Validate PowerShell execution sandbox security

## Phase 8: Deployment & Distribution

### 8.1 Packaging **[desktop-gui-developer]**
- [ ] Create single-file executable build
- [ ] Implement dependency bundling
- [ ] Create installation documentation
- [ ] Design user onboarding guide
- [ ] Create troubleshooting documentation
- [ ] Package PowerShell rules with executable

### 8.2 Documentation **[desktop-gui-developer + powershell-security-rules-developer]**
- [ ] Write administrator guide
- [ ] Create technical reference documentation for PowerShell rules
- [ ] Document API specifications for future expansion
- [ ] Create partner integration guide
- [ ] Write security and compliance documentation

## Phase 9: Future Preparation

### 9.1 Web Application Foundation **[webapp-coder-expert + db-expert]**
- [ ] Design database schema for PostgreSQL integration
- [ ] Create API endpoint specifications
- [ ] Design multi-tenant architecture
- [ ] Plan authentication and authorization framework
- [ ] Create data migration utilities from desktop exports

### 9.2 Continuous Monitoring Preparation **[webapp-coder-expert + db-expert]**
- [ ] Design scheduled scanning framework
- [ ] Create change notification system
- [ ] Plan alerting and notification infrastructure
- [ ] Design trend analysis database schema
- [ ] Create audit trail and compliance reporting

## Development Guidelines

### Development Environment Setup
**Current Phase: Native Windows Development**
- Primary development on Windows 11 (via RDP lab or miniPC)
- Visual Studio 2022 or VS Code with C# extensions
- PowerShell ISE or VS Code for rule development
- Windows SDK for WPF development
- Git for version control

### Subagent Collaboration Workflow
1. **powershell-security-rules-developer**: Creates rules in `/indicators` folder first
2. **desktop-gui-developer**: Implements C# application to execute and integrate rules
3. **Integration Testing**: Both agents validate rule execution and result processing
4. **Iteration**: Rules refined based on desktop application testing feedback

### Code Standards
- Follow secure coding practices
- Implement comprehensive error handling
- Use async/await patterns for I/O operations
- Follow dependency injection patterns
- Maintain separation of concerns between UI, business logic, and data access
- PowerShell rules must follow standardized output format for C# consumption

### Security Requirements
- Operate with principle of least privilege
- Never log or store sensitive credentials
- Encrypt all data in transit and at rest
- Implement secure authentication mechanisms
- Follow OWASP secure coding guidelines
- Secure PowerShell execution sandboxing

### Performance Targets
- Complete full scan of 10K users/5K computers within 30 minutes
- Support environments up to 100K objects
- Minimal impact on domain controller performance
- Memory usage optimization for large result sets
- Responsive UI during long-running operations