# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

IronVeil is an Identity Security Scanner application that identifies and assesses common identity security misconfigurations and threats within both on-premises Active Directory (AD) and Microsoft Entra ID environments. The current phase focuses on developing a standalone Windows desktop application.

## Architecture

### Core Components
- **Scan Engine**: Orchestrates data collection from AD and Entra ID, applies security indicator checks, generates findings
- **Data Collection Modules**:
  - **Active Directory Collector**: Uses LDAP queries, PowerShell cmdlets (ActiveDirectory module), WMI
  - **Entra ID Collector**: Leverages Microsoft Graph API, Azure AD PowerShell cmdlets
- **Security Analyzer**: Processes data against predefined security indicators (rules in `/indicators` folder)
- **Reporting Module**: Generates reports (PDF, HTML) and machine-readable outputs (CSV, JSON)
- **User Interface**: Simple WPF-based GUI for initiating scans and viewing results

### Technology Stack (Desktop App)
- **Core Language**: C# (.NET 8)
- **UI Framework**: WPF (Windows Presentation Foundation)
- **AD Integration**: System.DirectoryServices for LDAP queries
- **PowerShell Integration**: System.Management.Automation for cmdlet execution
- **Graph API**: Microsoft Graph SDK for Entra ID queries
- **Reporting**: QuestPDF for PDF generation, OxyPlot/LiveCharts for visualizations
- **CLI Support**: System.CommandLine for headless execution
- **Packaging**: Single-file .exe using .NET Publish

### Data Flow
1. User initiates scan via UI (typically local environment with current user rights)
2. Authentication to AD (local credentials) and Entra ID (OAuth 2.0/service principal)
3. Data collection from domain controllers and Microsoft Graph API endpoints
4. Security analysis using rule engine from `/indicators` folder
5. Report generation and dashboard population

## Development Structure

### Key Directories
- `/indicators/` - Security check rules and implementation patterns
  - `/pk-reference/` - Reference materials for security checks to be used only by the rule-expert-writer as a learning, do not reuse code from here.
  - `implementation-patterns.md` - Common patterns for security assessments
  - `security-check-pseudocode.md` - Templates for implementing checks
- `PRD.md` - Product Requirements Document
- `Identity Security Indicators (checks).md` - Detailed list of security indicators

### Specialized Agents
The project is designed to work with specialized subagents:
1. **powershell-security-rules-developer**: Develops PowerShell-based security check rules in `/indicators` folder following patterns in `implementation-patterns.md` and `security-check-pseudocode.md`. Creates rules that interface with the C# desktop application through standardized PowerShell cmdlet execution.
2. **desktop-gui-developer**: Handles all WPF desktop application development including UI design, C#/.NET backend, LDAP/Graph API integration, rule engine that executes PowerShell scripts, and report generation.
3. **webapp-coder-expert**: For future web application (later phase)
4. **db-expert**: For PostgreSQL integration (later phase)

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
**Platform**: Native Windows Development (Windows 11)
**IDE Options**:
- Visual Studio 2022 (recommended for WPF development and debugging)
- VS Code with C# Dev Kit extension (alternative)
- PowerShell ISE or VS Code for PowerShell rule development

### Build and Test Commands
Currently no build system is set up. The desktop-gui-developer should establish:
- `dotnet build` - Build the solution
- `dotnet test` - Run unit tests  
- `dotnet run` - Run application for debugging
- `dotnet publish -r win-x64 --self-contained --single-file` - Create single-file executable
- PowerShell test framework for validating security rules
- `Test-SecurityRule -RuleName "RuleName"` - Test individual PowerShell rules

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

### Subagent Workflow
1. **powershell-security-rules-developer** creates security rules in `/indicators` folder:
   - Follow patterns from `implementation-patterns.md` and `security-check-pseudocode.md`
   - Create standardized PowerShell scripts with proper metadata
   - Ensure rules can be executed by C# application through System.Management.Automation
   - Test rules independently before integration

2. **desktop-gui-developer** builds the desktop application:
   - Implement rule engine that can load and execute PowerShell scripts from `/indicators`
   - Create WPF UI following the technology stack specifications
   - Integrate LDAP queries and Microsoft Graph API calls
   - Implement report generation in multiple formats

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

**Required Output Format:**
```powershell
# Rules must return standardized objects
return @{
    CheckId = "rule-identifier"
    Timestamp = Get-Date
    Status = "Success|Failed|Error"  
    Score = 75
    Findings = @(
        @{
            ObjectName = "affected-object"
            RiskLevel = "High"
            Description = "issue description" 
            Remediation = "fix instructions"
        }
    )
    Message = "Summary message"
    AffectedObjects = 5
    IgnoredObjects = 2
}
```

**Error Handling Requirements:**
- Consistent try/catch blocks with standardized error objects
- Graceful degradation for permission issues
- Timeout handling for long-running queries
- All security rules must be testable both independently and through the desktop application

When working on this project:
- Focus on the desktop application (current phase)
- Security rules should be developed in the `/indicators` folder by powershell-security-rules-developer
- Follow the implementation patterns documented in the indicators directory
- Use the pseudocode templates for consistent security check implementation
- Ensure all code adheres to security best practices for identity assessment tools
- Reports should be generated in multiple formats (JSON for partner integration, PDF/HTML for human consumption)

## Project Goals

The primary goal is to provide an Identity Attack Surface overview through:
- Comprehensive dashboard or exportable JSON for external systems
- Detection of Indicators of Exposure (IoEs) and Indicators of Compromise (IoCs)
- Risk assessment and remediation guidance
- Support for both on-premises AD and cloud Entra ID environments
- Future API support for partner integrations (web application phase)