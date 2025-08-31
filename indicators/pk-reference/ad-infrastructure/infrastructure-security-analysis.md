# Active Directory Infrastructure Security Analysis

## Overview

Active Directory Infrastructure Security (Weight: 7) represents the second-highest priority category in Purple Knight, focusing on core AD components that, when compromised, can lead to complete domain takeover. This analysis examines critical infrastructure vulnerabilities and their exploitation methods.

## Critical Infrastructure Attack Vectors

### 1. DCShadow Attacks (Indicator ID: 13)

#### Attack Overview
DCShadow is an advanced persistence technique that allows attackers to register a fake domain controller and inject malicious changes into Active Directory through normal replication processes.

#### Technical Implementation
```
1. Prerequisites
   ├── Domain Admin privileges or equivalent  
   ├── Network access to domain controllers
   └── Mimikatz or similar toolset

2. Fake DC Registration
   ├── Create computer object with DC attributes
   ├── Register DC in Configuration partition
   └── Modify ServicePrincipalNames for replication

3. Malicious Replication  
   ├── Inject objects/attributes through DsAddEntry
   ├── Use DsReplicaAdd for change propagation
   └── Remove fake DC registration to avoid detection
```

#### Attack Capabilities
- **Schema Modifications**: Inject malicious attributes or classes
- **Object Creation**: Create backdoor administrative accounts
- **Permission Changes**: Modify ACLs on high-value objects
- **Group Membership**: Add accounts to privileged groups

#### Detection Evasion
- **No Security Events**: Bypasses traditional security logging (4728, 4732, 4756)
- **Legitimate Replication**: Uses normal AD replication protocols
- **Short-Lived Registration**: Temporary DC registration minimizes detection window
- **Administrative Blind Spots**: Changes appear to originate from domain controllers

#### Business Impact
- **Persistent Backdoors**: Creates difficult-to-detect access mechanisms
- **Privilege Escalation**: Grants arbitrary administrative access
- **Compliance Violations**: Undetected changes violate audit requirements
- **Detection Bypass**: Evades most traditional security controls

#### Advanced Mitigation
- **Replication Monitoring**: Monitor for unusual replication patterns
- **DC Registration Alerting**: Alert on new domain controller registrations
- **Change Auditing**: Advanced AD change detection beyond standard logs
- **Network Segmentation**: Restrict replication traffic to legitimate DCs

### 2. Zerologon Vulnerability (CVE-2020-1472) (Indicator ID: 36)

#### Vulnerability Details
Critical cryptographic flaw in Microsoft's implementation of AES-CFB8 encryption within the Netlogon protocol, allowing complete domain compromise.

#### Exploitation Process
```
1. Initial Exploitation
   ├── Send crafted Netlogon authentication requests
   ├── Exploit weak IV usage in AES-CFB8 encryption
   └── Reset domain controller machine account password

2. Authentication Bypass
   ├── Authenticate as domain controller machine account  
   ├── Use empty password after successful reset
   └── Gain domain controller privileges

3. Privilege Escalation
   ├── Extract Domain Admin credentials
   ├── Create persistent administrative access
   └── Establish domain-wide control
```

#### Attack Prerequisites
- **Network Access**: Direct or indirect access to domain controller
- **UDP Port 135**: Netlogon RPC endpoint access
- **No Authentication**: Attack works without any domain credentials

#### Technical Impact
- **Machine Account Reset**: Permanently damages domain controller trust
- **Authentication Bypass**: Complete circumvention of authentication controls
- **Credential Access**: Full access to domain credential database
- **Domain Takeover**: Complete administrative control over domain

#### Remediation Requirements
- **Critical Patching**: Microsoft patches KB4566424, KB4568831
- **DC Restart Required**: Patches require domain controller restart
- **Trust Restoration**: May require domain controller re-promotion
- **Incident Response**: Treat positive detection as critical incident

### 3. PrintNightmare Vulnerability Complex (Indicator ID: 77)

#### Vulnerability Overview
Multiple critical vulnerabilities in Windows Print Spooler service enabling local privilege escalation and remote code execution.

#### Attack Vectors

**Local Privilege Escalation (CVE-2021-1675)**
```
1. Point and Print Exploitation
   ├── Abuse Point and Print functionality
   ├── Install malicious printer drivers
   └── Execute code with SYSTEM privileges

2. Driver Installation Abuse  
   ├── Bypass driver signature requirements
   ├── Load malicious drivers through spooler
   └── Gain SYSTEM-level access
```

**Remote Code Execution (CVE-2021-34527)**
```
1. Remote Driver Installation
   ├── Authenticate to target print server
   ├── Install malicious printer drivers remotely
   └── Execute arbitrary code on target system

2. Authentication Coercion
   ├── Force target to authenticate to attacker system
   ├── Relay authentication to other services
   └── Gain access to additional resources
```

#### Domain Controller Impact
When Print Spooler runs on domain controllers:
- **Direct DC Compromise**: RCE on domain controllers = domain takeover
- **Credential Theft**: Access to domain credential database
- **Service Disruption**: Spooler crashes impact domain services
- **Coercion Attacks**: Force DC authentication for credential relay

#### Business Risk Assessment
- **Critical Infrastructure**: Domain controllers are high-value targets
- **Wide Attack Surface**: Print Spooler enabled by default on many systems
- **Easy Exploitation**: Public exploits available for both vulnerabilities  
- **Lateral Movement**: Facilitates movement across domain infrastructure

#### Comprehensive Mitigation
- **Service Hardening**: Disable Print Spooler on domain controllers
- **Group Policy Controls**: Configure Point and Print restrictions
- **Network Segmentation**: Block SMB access to print endpoints
- **Driver Policies**: Implement driver installation restrictions

### 4. Certificate Infrastructure Attacks (Indicator ID: 86)

#### Weak Certificate Analysis
Purple Knight identifies certificates with cryptographic weaknesses that can be exploited for authentication bypass and privilege escalation.

#### Vulnerable Configurations
- **Small RSA Keys**: Keys smaller than 2048 bits vulnerable to factorization
- **Weak Hash Algorithms**: MD5, SHA-1 susceptible to collision attacks
- **DSA Certificates**: Mathematical weaknesses in DSA implementation
- **Expired Certificates**: Still accepted by some applications

#### Certificate-Based Attack Methods

**Weak Key Factorization**
```
1. Certificate Discovery
   ├── Enumerate certificates with small key sizes
   ├── Extract public key for analysis
   └── Identify factorizable keys

2. Private Key Recovery
   ├── Apply factorization algorithms (Pollard's rho, etc.)
   ├── Recover private key from public key
   └── Create certificate with recovered private key

3. Authentication Bypass
   ├── Use recovered certificate for authentication
   ├── Impersonate certificate subject
   └── Gain unauthorized system access
```

**Hash Collision Attacks**  
```
1. Certificate Analysis
   ├── Identify certificates using weak hash algorithms
   ├── Assess collision attack feasibility
   └── Generate collision pairs

2. Certificate Forgery
   ├── Create certificate with same hash as legitimate cert
   ├── Use collision to bypass certificate validation
   └── Impersonate legitimate certificate holder
```

#### ADCS-Specific Vulnerabilities
- **Template Misconfiguration**: Dangerous certificate template permissions
- **CA Permissions**: Excessive permissions on Certificate Authority
- **Certificate Enrollment**: Vulnerable enrollment processes

#### PKI Infrastructure Impact
- **Authentication Bypass**: Compromised certificates enable system impersonation
- **Code Signing**: Malware signing with compromised certificates
- **TLS/SSL Compromise**: Man-in-the-middle attacks with forged certificates
- **Non-Repudiation Loss**: Compromised signing certificates lose legal value

### 5. AdminSDHolder Security (Indicator ID: 55)

#### AdminSDHolder Mechanism
Critical AD security feature that maintains consistent permissions on privileged accounts through Security Descriptor Propagation (SDProp) process.

#### Attack Vector Analysis
```
1. Permission Modification
   ├── Gain write access to AdminSDHolder object
   ├── Modify Access Control List (ACL) on AdminSDHolder
   └── Add malicious permissions or remove protective ones

2. Propagation Wait
   ├── Wait for SDProp process (runs every 60 minutes)
   ├── Changes propagate to all privileged accounts
   └── Malicious permissions become active

3. Privilege Exercise
   ├── Use newly granted permissions on privileged accounts
   ├── Modify group memberships or passwords
   └── Establish persistent administrative access
```

#### Affected Privileged Groups
- Domain Admins
- Enterprise Admins  
- Schema Admins
- Administrators
- Account Operators
- Backup Operators
- Server Operators
- Print Operators

#### Attack Advantages
- **Stealth Operation**: Changes appear legitimate through normal AD processes
- **Wide Impact**: Affects all members of privileged groups
- **Persistence**: Maintains access even if direct group memberships change
- **Delayed Activation**: 60-minute delay provides attack window

#### Detection and Response
- **ACL Monitoring**: Monitor AdminSDHolder for unauthorized changes
- **SDProp Tracking**: Alert on security descriptor propagation events
- **Privilege Auditing**: Regular verification of privileged account permissions
- **Rapid Response**: Immediate restoration of proper AdminSDHolder ACL

### 6. SID History Injection (Indicator ID: 23)

#### Attack Mechanism
SID History attribute allows user objects to retain access from previous domains during migrations, but can be abused for privilege escalation and persistence.

#### Injection Process  
```
1. Privilege Requirement
   ├── Domain Admin privileges or equivalent
   ├── Access to domain controller
   └── Knowledge of target privileged SIDs

2. SID Injection
   ├── Identify target user account for injection
   ├── Add privileged SID to SIDHistory attribute
   └── Verify injection successful

3. Access Exercise
   ├── Authenticate as modified user account
   ├── Access resources using injected SID privileges
   └── Maintain stealth through legitimate account usage
```

#### Common Privileged SIDs
- **Domain Admins**: S-1-5-21-[domain]-512
- **Enterprise Admins**: S-1-5-21-[root domain]-519  
- **Schema Admins**: S-1-5-21-[root domain]-518
- **Administrators**: S-1-5-32-544

#### Attack Benefits
- **Stealth Persistence**: Difficult to detect through normal group auditing
- **Cross-Domain Privilege**: Can inject SIDs from trusted domains
- **Backup Access**: Provides alternative access path if primary privileges removed
- **Audit Bypass**: May not trigger traditional privilege escalation alerts

#### Detection Strategy
- **SIDHistory Auditing**: Regular enumeration of accounts with SIDHistory
- **Privileged SID Monitoring**: Alert on well-known privileged SIDs in SIDHistory
- **Cross-Domain Analysis**: Verify legitimacy of cross-domain SID references
- **Historical Comparison**: Compare current SIDHistory against known baselines

## Infrastructure Defense Strategy

### 1. Preventive Security Controls

#### Domain Controller Hardening
- **Service Minimization**: Disable unnecessary services on domain controllers
- **Network Isolation**: Implement domain controller network segmentation
- **Patch Management**: Priority patching for domain controllers
- **Access Control**: Restrict physical and logical access to DCs

#### Replication Security
- **Replication Monitoring**: Monitor all replication traffic and patterns
- **DC Authentication**: Verify authenticity of replication partners
- **Change Auditing**: Advanced change detection beyond standard logs
- **Network Controls**: Restrict replication to legitimate DCs only

#### Certificate Infrastructure Security
- **Template Hardening**: Secure certificate template configurations
- **CA Protection**: Implement CA role separation and access controls
- **Key Management**: Secure private key storage and access
- **Certificate Lifecycle**: Proper certificate issuance, renewal, and revocation

### 2. Detective Security Controls

#### Advanced Monitoring
- **SIEM Integration**: Centralized logging and correlation of infrastructure events
- **Behavioral Analytics**: Machine learning for anomaly detection
- **Threat Hunting**: Proactive searching for infrastructure compromise indicators
- **Forensic Readiness**: Log retention and analysis capabilities

#### Real-Time Alerting
- **Critical Change Detection**: Immediate alerts for high-risk infrastructure changes
- **Service Anomalies**: Unusual service behavior or configuration changes
- **Authentication Anomalies**: Abnormal authentication patterns to infrastructure
- **Network Traffic Analysis**: Unusual network patterns involving DCs

### 3. Response Capabilities

#### Incident Response
- **Infrastructure Compromise Procedures**: Specific playbooks for DC compromise
- **Emergency Isolation**: Capability to quickly isolate compromised infrastructure
- **Backup Restoration**: Tested procedures for infrastructure recovery
- **Communication Plans**: Internal and external communication during incidents

#### Recovery Planning
- **Business Continuity**: Maintaining operations during infrastructure compromise
- **Disaster Recovery**: Complete infrastructure rebuild capabilities
- **Data Protection**: Ensuring data integrity during incident response
- **Lessons Learned**: Post-incident analysis and improvement processes

This infrastructure security analysis provides comprehensive understanding of the critical components that Purple Knight monitors, enabling organizations to protect the foundational elements of their Active Directory environments.