# Entra ID Security Analysis - Purple Knight Indicators

## Overview

Entra ID Security (Weight: 7) represents a critical focus area for Purple Knight, addressing the growing importance of cloud identity security in hybrid environments. This analysis examines key Entra ID vulnerabilities and attack vectors that Purple Knight detects.

## Critical Entra ID Attack Vectors

### 1. Excessive API Permissions (Indicator ID: 124)

#### Attack Overview
Applications with excessive Microsoft Graph API permissions can be exploited for privilege escalation, leading to Global Administrator access and complete tenant takeover.

#### High-Risk Permissions

**RoleManagement.ReadWrite.Directory**
- **Capability**: Can assign any role to any principal in the directory
- **Risk Level**: **Critical** - Direct path to Global Administrator
- **Attack Scenario**: Assign Global Administrator role to attacker-controlled account

**AppRoleAssignment.ReadWrite.All**  
- **Capability**: Can assign application permissions to any service principal
- **Risk Level**: **High** - Can escalate application privileges
- **Attack Scenario**: Grant additional dangerous permissions to compromised application

**Directory.ReadWrite.All**
- **Capability**: Full read/write access to directory objects
- **Risk Level**: **High** - Complete directory manipulation capability
- **Attack Scenario**: Modify user attributes, group memberships, authentication methods

**User.ReadWrite.All**
- **Capability**: Read and write all user profile information
- **Risk Level**: **Medium-High** - User impersonation and data access
- **Attack Scenario**: Reset user passwords, modify MFA settings

#### Application Compromise Scenarios

**Service Principal Credential Theft**
```
1. Application Compromise
   ├── Steal application client secret or certificate
   ├── Extract credentials from application configuration
   └── Obtain access tokens for Microsoft Graph API

2. Permission Discovery
   ├── Enumerate current application permissions
   ├── Identify high-risk permissions available
   └── Assess privilege escalation potential

3. Privilege Escalation
   ├── Use RoleManagement.ReadWrite.Directory permission
   ├── Assign Global Administrator role to attacker account
   └── Gain complete tenant administrative access
```

**Application Registration Abuse**
```
1. Administrative Access
   ├── Compromise account with Application Administrator role
   ├── Access Azure portal or PowerShell/CLI tools
   └── Identify target applications with excessive permissions

2. Credential Generation
   ├── Add new client secret to existing application
   ├── Generate certificate for application authentication
   └── Download credentials for offline use

3. API Exploitation
   ├── Authenticate to Microsoft Graph using stolen credentials
   ├── Exploit excessive permissions for privilege escalation
   └── Maintain persistent access through application identity
```

#### Business Impact
- **Complete Tenant Takeover**: Global Administrator access to entire Entra ID tenant
- **Data Exfiltration**: Access to all organizational data through Graph API
- **Persistent Backdoor**: Application-based access survives user account changes
- **Compliance Violations**: Unauthorized access to regulated data

#### Detection and Mitigation
- **Permission Auditing**: Regular review of all application permissions
- **Least Privilege**: Grant minimum necessary permissions to applications  
- **Application Monitoring**: Monitor application authentication and API usage
- **Consent Policies**: Implement admin consent requirements for high-risk permissions

### 2. Privileged Guest Account Security

#### Attack Vector Analysis
External guest accounts with elevated privileges represent significant security risks, as they may not be subject to organizational security controls.

#### Risk Scenarios

**External Administrator Access**
- **Risk**: Guest accounts with Global Administrator or other privileged roles
- **Attack Vector**: Compromised external organization leading to privileged access
- **Impact**: Administrative access controlled by external entity

**Cross-Tenant Privilege Escalation**  
- **Risk**: Guest accounts with privileges in multiple tenants
- **Attack Vector**: Single compromise affects multiple organizations
- **Impact**: Lateral movement across organizational boundaries

**Privileged Guest Persistence**
- **Risk**: Forgotten guest accounts retaining elevated privileges
- **Attack Vector**: Long-term unauthorized access through dormant accounts
- **Impact**: Unmonitored privileged access to organizational resources

#### Mitigation Strategy
- **Guest Account Auditing**: Regular review of all guest accounts and their privileges
- **Access Reviews**: Periodic certification of guest account necessity and permissions
- **Conditional Access**: Apply stricter policies to guest accounts
- **Privilege Minimization**: Grant minimum necessary privileges to external users

### 3. Legacy Authentication Vulnerabilities  

#### Authentication Protocol Risks
Legacy authentication protocols lack modern security features like MFA support and conditional access policy enforcement.

#### Vulnerable Protocols
- **Basic Authentication**: Username/password without MFA capability
- **Legacy Exchange Protocols**: POP3, IMAP, SMTP authentication
- **Office 2016 and Earlier**: Older Office versions using legacy protocols
- **Third-Party Applications**: Applications not supporting modern authentication

#### Attack Exploitation
```
1. Credential Harvesting
   ├── Password spray attacks against legacy endpoints
   ├── Brute force attacks without MFA protection
   └── Credential stuffing with leaked password databases

2. Protocol Exploitation  
   ├── Intercept legacy authentication traffic
   ├── Replay captured authentication tokens
   └── Bypass modern security controls

3. Application Targeting
   ├── Identify applications using legacy authentication
   ├── Target accounts with legacy protocol access
   └── Gain unauthorized access to email and documents
```

#### Business Risk
- **MFA Bypass**: Legacy protocols circumvent multi-factor authentication
- **Conditional Access Bypass**: Cannot enforce location or device policies
- **Password Attacks**: Vulnerable to brute force and spray attacks
- **Compliance Issues**: May violate security policy requirements

### 4. Conditional Access Policy Gaps

#### Policy Configuration Issues
Missing or misconfigured conditional access policies create security gaps in cloud identity protection.

#### Common Policy Gaps

**Privileged Account Protection**
- **Risk**: Admin accounts without MFA requirements
- **Attack Vector**: Compromised admin credentials without additional verification
- **Mitigation**: Enforce MFA for all privileged roles

**Geographic Access Controls**
- **Risk**: No location-based access restrictions  
- **Attack Vector**: Unauthorized access from unexpected locations
- **Mitigation**: Implement location-based conditional access policies

**Device Compliance Requirements**
- **Risk**: Access from unmanaged or non-compliant devices
- **Attack Vector**: Compromised personal devices accessing corporate resources
- **Mitigation**: Require device compliance for corporate resource access

**Application-Specific Controls**
- **Risk**: Critical applications without additional security controls
- **Attack Vector**: Direct access to sensitive applications after initial authentication
- **Mitigation**: Implement stepped-up authentication for high-risk applications

#### Implementation Strategy
- **Risk-Based Policies**: Implement adaptive authentication based on risk signals
- **Staged Rollout**: Gradually implement policies with monitoring and adjustment
- **Policy Testing**: Use report-only mode before enforcing new policies
- **User Experience**: Balance security requirements with usability

### 5. Multi-Factor Authentication Gaps

#### MFA Configuration Weaknesses
Incomplete MFA implementation or weak MFA methods create authentication vulnerabilities.

#### MFA Bypass Techniques

**SMS/Voice Call Attacks**
- **SIM Swapping**: Attacker gains control of victim's phone number
- **Social Engineering**: Manipulation of telecom providers for number transfer
- **Interception**: SMS interception through various technical methods

**Authentication App Compromise**  
- **Device Compromise**: Malware on device with authenticator app
- **Backup Codes**: Theft or social engineering for backup authentication codes
- **App Vulnerabilities**: Exploitation of authenticator application weaknesses

**MFA Fatigue Attacks**
- **Notification Bombing**: Overwhelming users with MFA requests until approval
- **Social Engineering**: Convincing users to approve unauthorized requests
- **Timing Attacks**: MFA requests during off-hours when users are less vigilant

#### Secure MFA Implementation
- **FIDO2/WebAuthn**: Hardware-based authentication for highest security
- **Microsoft Authenticator**: App-based push notifications with number matching
- **Backup Method Diversity**: Multiple backup methods to prevent single point of failure
- **User Training**: Education on MFA security best practices

### 6. Identity Protection and Risk Detection

#### Risk-Based Authentication
Entra ID Identity Protection provides risk-based authentication and automated remediation capabilities.

#### Risk Signal Analysis

**Sign-In Risk Factors**
- **Impossible Travel**: Geographically impossible user travel patterns
- **Anonymous IP Addresses**: Access from Tor or other anonymization services
- **Malware Linked IP**: Access from IP addresses associated with malware
- **Unfamiliar Sign-In Properties**: Unusual locations, devices, or applications

**User Risk Factors**
- **Leaked Credentials**: User credentials found in breach databases
- **Suspicious Activity**: Unusual user behavior patterns
- **Azure AD Threat Intelligence**: Microsoft threat intelligence indicators
- **Offline Analysis**: Batch processing of user risk indicators

#### Automated Response Capabilities
- **Risk-Based Conditional Access**: Automatic policy enforcement based on risk level
- **Self-Service Password Reset**: User-initiated password reset for medium risk
- **Administrative Investigation**: High-risk users flagged for manual review
- **Account Remediation**: Automatic password reset and re-registration requirements

### 7. Application Security and OAuth Flows

#### OAuth/OpenID Connect Vulnerabilities
Misconfigured OAuth flows and application registrations create security vulnerabilities.

#### Common OAuth Attack Vectors

**Authorization Code Interception**
- **Redirect URI Manipulation**: Attacker redirects authorization codes to controlled endpoint
- **Man-in-the-Middle**: Interception of authorization flows
- **Mobile App Vulnerabilities**: Insecure redirect URI handling in mobile applications

**Consent Phishing**
- **Malicious Applications**: Fake applications requesting legitimate-looking permissions
- **Social Engineering**: Convincing users to consent to malicious applications
- **Permission Escalation**: Applications requesting more permissions than needed

**Token Theft and Replay**
- **Access Token Theft**: Stealing access tokens for API access
- **Refresh Token Abuse**: Long-lived refresh tokens enabling persistent access
- **Token Scope Expansion**: Using tokens beyond intended scope

#### Secure Application Development
- **PKCE Implementation**: Proof Key for Code Exchange for public clients
- **Secure Redirect URIs**: Proper validation and configuration of redirect URIs
- **Minimal Permissions**: Request only necessary permissions for application functionality
- **Token Management**: Secure storage and handling of authentication tokens

## Comprehensive Entra ID Defense Strategy

### 1. Identity Governance

#### Access Management
- **Privileged Identity Management (PIM)**: Just-in-time administrative access
- **Access Reviews**: Regular certification of user access and permissions
- **Entitlement Management**: Automated access provisioning and deprovisioning
- **Identity Lifecycle Management**: Automated user lifecycle processes

#### Application Governance
- **Application Registration Management**: Controlled application registration processes
- **Permission Management**: Regular auditing and cleanup of application permissions
- **Consent Framework**: Admin consent requirements for high-risk permissions
- **Application Monitoring**: Continuous monitoring of application behavior

### 2. Advanced Security Controls

#### Conditional Access
- **Risk-Based Policies**: Authentication requirements based on calculated risk
- **Device-Based Access**: Require managed or compliant devices for access
- **Application Protection**: App-specific security requirements and controls
- **Session Controls**: Real-time session monitoring and control

#### Identity Protection
- **Risk Detection**: Real-time and offline risk signal analysis
- **Automated Remediation**: Policy-based automatic response to detected risks
- **Investigation Tools**: Advanced tools for investigating identity security incidents
- **Reporting and Analytics**: Comprehensive visibility into identity security posture

### 3. Monitoring and Detection

#### Security Information and Event Management
- **Azure AD Logs**: Comprehensive logging of all identity-related activities
- **API Monitoring**: Microsoft Graph API usage monitoring and analysis
- **Application Insights**: Application-specific security monitoring
- **Security Center Integration**: Centralized security monitoring and alerting

#### Threat Intelligence
- **Microsoft Threat Intelligence**: Integration with Microsoft's global threat intelligence
- **Custom Indicators**: Organization-specific threat indicators and rules
- **Threat Hunting**: Proactive searching for advanced threats in identity infrastructure
- **Incident Response**: Coordinated response to identity security incidents

This Entra ID security analysis provides comprehensive coverage of cloud identity threats that Purple Knight helps organizations identify and mitigate in their hybrid identity environments.