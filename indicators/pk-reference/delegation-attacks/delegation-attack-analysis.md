# Active Directory Delegation Attack Analysis

## Overview

Active Directory Delegation (Weight: 3) represents a complex attack surface that, while assigned lower priority in Purple Knight's weighting system, can provide critical privilege escalation paths for sophisticated attackers. This analysis examines delegation-based attack vectors and their security implications.

## Understanding Active Directory Delegation

### Delegation Types and Mechanisms

#### Traditional Constrained Delegation
- **Purpose**: Allows services to impersonate users to specific backend services
- **Configuration**: Set via msDS-AllowedToDelegateTo attribute
- **Protocol**: Uses Kerberos S4U2Self and S4U2Proxy extensions
- **Scope**: Limited to predefined service targets

#### Unconstrained Delegation  
- **Purpose**: Allows services to impersonate users to any service
- **Configuration**: TRUSTED_FOR_DELEGATION flag in userAccountControl
- **Protocol**: Caches user TGTs in service memory
- **Scope**: Unlimited impersonation capability

#### Resource-Based Constrained Delegation (RBCD)
- **Purpose**: Modern delegation model with target-controlled authorization
- **Configuration**: msDS-AllowedToActOnBehalfOfOtherIdentity on target resource
- **Protocol**: Uses S4U2Self and S4U2Proxy with reverse trust model
- **Scope**: Target resource controls which services can delegate

### Protocol Transition
- **Capability**: Convert non-Kerberos authentication to Kerberos tokens
- **Use Cases**: Web applications authenticating users via forms/certificates
- **Risk Factor**: Can impersonate any user without possessing their credentials

## Critical Delegation Attack Vectors

### 1. DCSync Rights Escalation (Indicator ID: 21)

#### Attack Overview
Non-default accounts with Directory Replication permissions can perform DCSync attacks to extract password hashes for all domain accounts.

#### Required Permissions for DCSync
```
DS-Replication-Get-Changes (GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
DS-Replication-Get-Changes-All (GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)  
DS-Replication-Get-Changes-In-Filtered-Set (GUID: 89e95b76-444d-4c62-991a-0facbeda640c)
```

#### Attack Execution Process
```
1. Account Compromise
   ├── Gain access to account with replication permissions
   ├── Verify account has required DS-Replication permissions
   └── Establish connection to domain controller

2. DCSync Execution
   ├── Use Mimikatz: lsadump::dcsync /user:krbtgt /domain:domain.com
   ├── Use Impacket: secretsdump.py domain/user@dc.domain.com
   └── Extract NTLM hashes and Kerberos keys for all accounts

3. Credential Usage
   ├── Use extracted KRBTGT hash for Golden Ticket attacks
   ├── Pass-the-hash with extracted administrator credentials
   └── Offline cracking of extracted password hashes
```

#### Common Misconfiguration Sources
- **Exchange Server Installation**: Grants excessive replication permissions to Exchange service accounts
- **Backup Software**: Database backup applications granted unnecessary replication rights
- **Custom Applications**: Poorly designed applications with over-privileged service accounts
- **Administrative Delegation**: Excessive permissions granted during delegation setup

#### Business Impact
- **Complete Credential Compromise**: Access to all domain account password hashes
- **Golden Ticket Capability**: KRBTGT hash enables unlimited domain access
- **Administrative Escalation**: Domain Admin hash extraction for immediate privilege escalation
- **Lateral Movement**: Credentials for lateral movement across entire domain

#### Advanced Detection
```powershell
# Find accounts with DCSync permissions
$rootDSE = Get-ADRootDSE
$domainDN = $rootDSE.DefaultNamingContext

(Get-Acl "AD:$domainDN").Access | Where-Object {
    $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|ExtendedRight" -and
    $_.AccessControlType -eq "Allow"
} | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType
```

### 2. Unconstrained Delegation Exploitation (Indicator ID: 16)

#### Attack Methodology
Services with unconstrained delegation cache TGTs of users who authenticate to them, enabling credential theft and impersonation.

#### Exploitation Process
```
1. Service Compromise
   ├── Identify servers with unconstrained delegation
   ├── Gain administrative access to delegated service
   └── Verify TGT caching capability

2. TGT Harvesting
   ├── Wait for high-value users to authenticate to service
   ├── Use Mimikatz: sekurlsa::tickets /export
   ├── Extract cached TGTs from LSASS memory
   └── Identify Domain Admin or other privileged tickets

3. Credential Impersonation
   ├── Import stolen TGTs: kerberos::ptt ticket.kirbi
   ├── Authenticate as impersonated user
   └── Access resources with stolen identity
```

#### Targeted Credential Harvesting
```
1. Service Identification
   ├── Enumerate servers with TRUSTED_FOR_DELEGATION flag
   ├── Identify high-traffic services (file shares, web servers)
   └── Assess likelihood of administrative access

2. Coercion Attacks
   ├── Force Domain Admins to authenticate to compromised service
   ├── Use printer bug or other coercion techniques
   └── Capture administrative TGTs for privilege escalation

3. Persistence Establishment
   ├── Use harvested admin credentials for persistent access
   ├── Create additional backdoor accounts
   └── Modify delegation settings for future access
```

#### High-Value Targets for Unconstrained Delegation
- **File Servers**: High user authentication frequency
- **Print Servers**: Often accessed by administrative accounts
- **Web Applications**: Potential for administrative authentication
- **Database Servers**: May receive administrative connections

### 3. Resource-Based Constrained Delegation (RBCD) Abuse (Indicator ID: 31)

#### Attack Vector Analysis
RBCD allows the target resource to control which accounts can delegate to it, but this can be abused when attackers control the delegating account.

#### RBCD Attack Process
```
1. Computer Account Control
   ├── Gain local administrative access to domain-joined computer
   ├── Obtain computer account credentials or hash
   └── Verify ability to modify computer account attributes

2. RBCD Configuration
   ├── Modify msDS-AllowedToActOnBehalfOfOtherIdentity attribute
   ├── Configure delegation from controlled account to target
   └── Verify delegation relationship establishment

3. Impersonation Attack
   ├── Use S4U2Self to obtain forwardable service ticket
   ├── Use S4U2Proxy to access target service as arbitrary user
   └── Gain administrative access to target system
```

#### Technical Implementation
```powershell
# Configure RBCD from COMPUTER1$ to TARGET$
$computer1 = Get-ADComputer "COMPUTER1"
$targetComputer = Get-ADComputer "TARGET"

$rbcdBytes = $computer1.ObjectSid.ToByteArray()
Set-ADComputer -Identity $targetComputer -PrincipalsAllowedToDelegateToAccount $computer1
```

#### Attack Scenarios

**Computer Account Takeover**
```
1. Local Admin Access
   ├── Compromise local administrator on domain computer
   ├── Extract computer account hash from registry/memory
   └── Verify computer account domain privileges

2. Target Selection
   ├── Identify high-value target computers (DCs, servers)
   ├── Verify write permissions on target msDS-AllowedToActOnBehalfOfOtherIdentity
   └── Configure RBCD relationship

3. Service Ticket Abuse
   ├── Request service ticket as Domain Admin to target
   ├── Use ticket for administrative access to target
   └── Establish persistence on compromised target
```

### 4. Constrained Delegation to Critical Services

#### Attack Vector Assessment
Services configured for constrained delegation to critical infrastructure services can be abused for privilege escalation.

#### High-Risk Delegation Targets
- **Domain Controllers**: LDAP, HOST, CIFS services
- **Certificate Authority**: HTTP services for web enrollment
- **DNS Servers**: DNS service for name resolution control
- **ADFS Servers**: HTTP services for federation token issuance

#### Exploitation Methodology
```
1. Service Account Compromise
   ├── Identify service accounts with constrained delegation
   ├── Assess delegation target services and their criticality
   └── Compromise service account credentials

2. Delegation Abuse
   ├── Use S4U2Self to obtain forwardable ticket for arbitrary user
   ├── Use S4U2Proxy to access delegated service as impersonated user
   └── Leverage access to delegated service for further privilege escalation

3. Critical Service Exploitation
   ├── Use delegated access to LDAP for directory modifications
   ├── Abuse HTTP delegation to CA for certificate issuance
   └── Exploit DNS delegation for name resolution manipulation
```

### 5. Protocol Transition Abuse

#### Attack Overview
Services with protocol transition capability can convert non-Kerberos authentication into Kerberos tokens for any user.

#### Technical Requirements
- **TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION** flag
- **S4U2Self** protocol support
- **Service Principal Name** configuration

#### Exploitation Process
```
1. Service Compromise
   ├── Identify services with protocol transition capability
   ├── Gain access to service account or service application
   └── Verify S4U2Self protocol support

2. Token Generation
   ├── Use S4U2Self to generate service ticket for any user
   ├── Specify target user (Domain Admin, Enterprise Admin)
   └── Obtain forwardable service ticket for impersonation

3. Service Access
   ├── Use generated ticket to access constrained delegation targets
   ├── Impersonate privileged users to backend services
   └── Escalate privileges through delegated service access
```

## Comprehensive Delegation Defense Strategy

### 1. Delegation Inventory and Assessment

#### Discovery and Documentation
```powershell
# Find accounts with unconstrained delegation
Get-ADUser -Filter * -Properties TrustedForDelegation | 
Where-Object {$_.TrustedForDelegation -eq $true}

Get-ADComputer -Filter * -Properties TrustedForDelegation | 
Where-Object {$_.TrustedForDelegation -eq $true}

# Find accounts with constrained delegation  
Get-ADUser -Filter * -Properties msDS-AllowedToDelegateTo | 
Where-Object {$_.msDS-AllowedToDelegateTo}

Get-ADComputer -Filter * -Properties msDS-AllowedToDelegateTo | 
Where-Object {$_.msDS-AllowedToDelegateTo}

# Find RBCD configurations
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | 
Where-Object {$_.msDS-AllowedToActOnBehalfOfOtherIdentity}
```

#### Risk Assessment
- **Business Justification**: Verify legitimate business need for each delegation
- **Service Criticality**: Assess the security impact of compromised delegated services  
- **User Population**: Evaluate which users authenticate to delegated services
- **Attack Surface**: Calculate potential privilege escalation paths

### 2. Delegation Hardening

#### Unconstrained Delegation Elimination
- **Service Migration**: Move services to constrained delegation where possible
- **Kerberos-Only Authentication**: Configure services for Kerberos-only authentication
- **Service Isolation**: Isolate services with unconstrained delegation
- **Monitoring Enhancement**: Implement enhanced monitoring for unconstrained delegation usage

#### Constrained Delegation Security
- **Target Minimization**: Limit delegation to minimum necessary services
- **Regular Review**: Periodic assessment of delegation configurations
- **Service Account Hardening**: Strengthen security of delegated service accounts
- **Permission Auditing**: Monitor changes to delegation configurations

#### RBCD Management
- **Change Control**: Implement approval process for RBCD modifications
- **Automated Monitoring**: Alert on changes to msDS-AllowedToActOnBehalfOfOtherIdentity
- **Regular Auditing**: Periodic review of all RBCD configurations
- **Documentation Requirements**: Document business justification for each RBCD relationship

### 3. Advanced Monitoring and Detection

#### Delegation Abuse Detection
- **Unusual S4U Requests**: Monitor for suspicious Service-for-User protocol usage
- **Cross-Service Authentication**: Detect authentication patterns inconsistent with normal business processes
- **Privilege Escalation Indicators**: Alert on sudden privilege increases through delegation
- **Ticket Anomalies**: Identify unusually long-lived or highly privileged delegation tickets

#### Behavioral Analytics
- **Service Authentication Patterns**: Establish baselines for normal delegation usage
- **Administrative Activity Correlation**: Correlate delegation usage with administrative actions
- **Time-Based Analysis**: Detect delegation usage during unusual time periods
- **Geographic Analysis**: Monitor delegation usage from unexpected locations

### 4. Incident Response Capabilities

#### Delegation Compromise Response
- **Immediate Isolation**: Capability to quickly disable compromised delegation relationships
- **Credential Reset**: Rapid reset of compromised service account credentials
- **Forensic Analysis**: Tools and procedures for investigating delegation abuse
- **Recovery Procedures**: Tested procedures for restoring secure delegation configurations

#### Long-term Remediation
- **Architecture Review**: Assessment of overall delegation architecture security
- **Service Redesign**: Recommendations for reducing delegation security risks
- **Security Control Enhancement**: Implementation of additional controls for delegation security
- **Training and Awareness**: Education for administrators on delegation security best practices

## Strategic Recommendations

### 1. Delegation Minimization
- **Zero-Trust Approach**: Challenge the necessity of each delegation relationship
- **Service Consolidation**: Reduce the number of services requiring delegation
- **Modern Authentication**: Migrate to modern authentication methods where possible
- **Alternative Architectures**: Consider service architectures that minimize delegation requirements

### 2. Enhanced Monitoring
- **SIEM Integration**: Incorporate delegation monitoring into security operations center
- **Advanced Analytics**: Implement machine learning for delegation abuse detection
- **Threat Intelligence**: Include delegation indicators in threat intelligence feeds
- **Regular Assessment**: Schedule periodic delegation security assessments

### 3. Long-term Security Improvement
- **Architecture Evolution**: Plan migration to more secure authentication architectures
- **Technology Upgrades**: Leverage newer Windows features for improved delegation security
- **Security Automation**: Implement automated controls for delegation management
- **Continuous Improvement**: Regular review and enhancement of delegation security practices

This comprehensive delegation attack analysis provides organizations with the knowledge needed to understand, detect, and mitigate delegation-based security risks in their Active Directory environments.