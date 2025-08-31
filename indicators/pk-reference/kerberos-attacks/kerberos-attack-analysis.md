# Kerberos Attack Analysis - Purple Knight Indicators

## Overview

Kerberos Security represents Purple Knight's highest-weighted category (Weight: 8), reflecting the critical importance of Kerberos protocol security in Active Directory environments. This analysis covers the major Kerberos attack vectors detected by Purple Knight and their real-world implications.

## Critical Kerberos Attack Vectors

### 1. Golden Ticket Attacks

#### Purple Knight Indicators
- **ID 17**: KRBTGT account with old password  
- **ID 71**: KRBTGT account with Resource-Based Constrained Delegation
- **ID 99**: Accounts with Constrained Delegation to KRBTGT

#### Attack Mechanics
Golden Ticket attacks exploit compromised KRBTGT account credentials to forge Ticket Granting Tickets (TGTs) with arbitrary privileges:

```
1. Credential Extraction Phase
   ├── DCSync attack to extract KRBTGT hash
   ├── Memory dump from domain controller
   └── Offline cracking of KRBTGT password

2. Ticket Forging Phase  
   ├── Create TGT with Domain Admin privileges
   ├── Set extended lifetime (10 years typical)
   └── Include any desired group memberships

3. Authentication Phase
   ├── Present forged TGT to domain controllers
   ├── Request service tickets for any resource
   └── Gain unlimited domain access
```

#### Real-World Impact
- **Complete Domain Control**: Access to all domain resources without restrictions
- **Stealth Operations**: Forged tickets appear legitimate to domain controllers  
- **Long-Term Persistence**: Tickets remain valid until KRBTGT password change
- **Cross-Domain Access**: Enterprise Admin tickets work across forest domains

#### Detection Challenges
- **No Authentication Logs**: Forged tickets don't generate failed authentication events
- **Legitimate Appearance**: Tickets pass standard Kerberos validation  
- **Lifetime Anomalies**: Only detectable through advanced ticket lifetime analysis
- **Rare KRBTGT Usage**: Normal KRBTGT activity is minimal, making detection difficult

#### Advanced Variations

**KRBTGT Resource-Based Constrained Delegation (ID: 71)**
- Allows similar Golden Ticket capabilities through delegation abuse
- Harder to detect than traditional Golden Tickets
- Exploits modern Windows Server delegation features

**Constrained Delegation to KRBTGT (ID: 99)**  
- Service accounts delegated to KRBTGT can forge tickets
- Often overlooked in delegation security reviews
- Provides backdoor Golden Ticket capability

### 2. Silver Ticket Attacks

While not explicitly listed as a top indicator, Silver Ticket attacks target specific services rather than domain-wide access:

#### Attack Characteristics
- **Service-Specific**: Targets individual service accounts rather than KRBTGT
- **Limited Scope**: Access restricted to specific services  
- **Stealth Factor**: Lower detection probability than Golden Tickets
- **Service Dependencies**: Requires knowledge of target service configurations

### 3. Kerberoasting Attacks

#### Purple Knight Indicator
- **ID 19**: Privileged users with Service Principal Names (SPNs)

#### Attack Process
```
1. SPN Discovery
   ├── LDAP queries to identify service accounts
   ├── PowerShell enumeration (Get-ADUser -Filter {ServicePrincipalNames -like "*"})
   └── Automated tools (BloodHound, PowerView)

2. TGS Request  
   ├── Request service tickets for target SPNs
   ├── No authentication to target service required
   └── Extract encrypted portion of TGS response

3. Offline Cracking
   ├── Extract service account password hash from TGS
   ├── Dictionary/brute force attack against hash
   └── Recover plaintext service account password
```

#### High-Value Targets
- **SQL Server Service Accounts**: Often have high privileges for database access
- **Exchange Service Accounts**: Email infrastructure administrative access
- **Custom Application Services**: Business-critical application access
- **Privileged User Accounts**: Domain/Enterprise Admins with SPNs

#### Business Impact
- **Service Account Compromise**: Direct access to critical services
- **Privilege Escalation**: Service accounts often over-privileged
- **Lateral Movement**: Service credentials enable further network access
- **Data Exfiltration**: Database and application access for data theft

#### Mitigation Strategies
- **Managed Service Accounts**: Use gMSA/MSA for automatic password management
- **Strong Passwords**: 25+ character complex passwords for service accounts
- **SPN Management**: Remove unnecessary SPNs from user accounts
- **Privilege Minimization**: Reduce service account privileges to necessary minimum

### 4. ASREPRoasting Attacks

#### Purple Knight Indicator  
- **ID 27**: Users with pre-authentication disabled

#### Attack Vector
```
1. Account Discovery
   ├── LDAP enumeration for DONT_REQUIRE_PREAUTH flag
   ├── PowerShell queries (Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true})
   └── Automated scanning tools

2. AS-REQ Without Pre-Auth
   ├── Send authentication request without encrypted timestamp
   ├── Receive AS-REP with encrypted user password hash
   └── No valid credentials required for this step

3. Offline Password Attack
   ├── Extract password hash from AS-REP response
   ├── Brute force/dictionary attack against hash
   └── Recover plaintext user password
```

#### Attack Advantages
- **No Authentication Required**: Can be performed without any domain credentials
- **User Enumeration**: Confirms valid usernames for further attacks
- **Password Recovery**: Direct path to user password compromise
- **Initial Access**: Often used as initial domain foothold technique

#### Common Scenarios
- **Legacy Compatibility**: Older applications requiring disabled pre-auth
- **Misconfiguration**: Accidental disabling during troubleshooting
- **Service Accounts**: Some service configurations disable pre-auth unnecessarily

#### Prevention
- **Pre-Authentication Enforcement**: Enable on all user accounts
- **Regular Auditing**: Monitor accounts with disabled pre-auth
- **Alternative Solutions**: Use modern authentication methods for legacy applications

### 5. Delegation Attacks

#### Purple Knight Indicators
- **ID 16**: Computer/user accounts with unconstrained delegation
- **ID 31**: Resource-Based Constrained Delegation on computers

#### Unconstrained Delegation Exploitation
```
1. Service Compromise
   ├── Gain administrative access to delegated service
   ├── Extract cached TGTs from service memory
   └── Identify high-value cached tickets

2. TGT Harvesting
   ├── Use Mimikatz to extract TGTs from LSASS
   ├── Identify Domain Admin or other privileged tickets
   └── Export tickets for offline use

3. Ticket Impersonation  
   ├── Import stolen TGTs into attack session
   ├── Access resources as impersonated users
   └── Maintain persistence through ticket renewal
```

#### Resource-Based Constrained Delegation (RBCD)
```
1. Computer Account Control
   ├── Gain administrative access to domain computer
   ├── Modify msDS-AllowedToActOnBehalfOfOtherIdentity attribute
   └── Configure delegation to target computer

2. Service Ticket Request
   ├── Request service ticket to target computer as arbitrary user
   ├── Present ticket for authentication to target
   └── Gain access as impersonated user account
```

#### Business Risks
- **Privilege Escalation**: Delegation often involves high-privilege accounts
- **Lateral Movement**: Access to multiple systems through cached tickets
- **Administrative Compromise**: Targeting of Domain Admin sessions
- **Stealth Operations**: Uses legitimate Kerberos delegation features

## Advanced Kerberos Attack Techniques

### Bronze Bit Attack (CVE-2020-17049)
- Exploits Kerberos delegation by modifying forwardable flag in service tickets
- Bypasses standard delegation restrictions
- Enables privilege escalation through certificate-based authentication

### Skeleton Key Attack  
- Implants backdoor password in domain controller memory
- Maintains normal authentication while allowing backdoor access
- Requires Domain Controller compromise to implement

### DCShadow Integration
- Uses fake domain controller to modify Kerberos-related attributes
- Can establish persistent Golden Ticket capabilities
- Bypasses normal security event logging

## Comprehensive Defense Strategy

### 1. Preventive Controls

#### KRBTGT Management
- **Regular Rotation**: Password change every 180 days maximum
- **Double Rotation**: Two password changes, 10 hours apart
- **Emergency Rotation**: Immediate rotation after suspected compromise

#### Service Account Hardening
- **Managed Service Accounts**: Migrate to gMSA where possible
- **Strong Passwords**: 25+ character complex passwords
- **Privilege Minimization**: Least privilege principle for service accounts
- **SPN Cleanup**: Remove unnecessary SPNs from user accounts

#### Delegation Security
- **Unconstrained Elimination**: Replace with constrained delegation
- **RBCD Validation**: Regular audit of RBCD configurations
- **Sensitive Account Protection**: Mark privileged accounts as sensitive

### 2. Detective Controls

#### Advanced Monitoring
- **Ticket Lifetime Analysis**: Detect unusually long-lived tickets  
- **Authentication Pattern Analysis**: Identify abnormal authentication behaviors
- **Service Ticket Anomalies**: Monitor for unusual service ticket requests
- **Delegation Usage Tracking**: Audit delegation-based authentications

#### SIEM Integration
- **Event Correlation**: Combine multiple Kerberos events for threat detection
- **Behavioral Analytics**: Machine learning for authentication anomaly detection  
- **Threat Intelligence**: Integration with known Kerberos attack indicators

### 3. Response Capabilities

#### Incident Response
- **Golden Ticket Response**: Immediate KRBTGT rotation and investigation
- **Service Account Compromise**: Immediate password reset and privilege review
- **Delegation Abuse**: Emergency delegation removal and access review

#### Forensic Analysis
- **Ticket Analysis**: Tools for analyzing suspicious Kerberos tickets
- **Timeline Reconstruction**: Correlating Kerberos events with other activities
- **Indicator Extraction**: Identifying compromise indicators for future detection

## Tools and Techniques for Purple Knight Operators

### Assessment Tools
- **Rubeus**: Comprehensive Kerberos attack toolkit
- **Impacket**: Python-based Kerberos exploitation tools  
- **BloodHound**: Graphical AD attack path analysis
- **PowerView**: PowerShell-based AD enumeration

### Detection Tools
- **Microsoft Defender for Identity**: Commercial Kerberos attack detection
- **Custom PowerShell Scripts**: Organization-specific monitoring capabilities
- **SIEM Rules**: Custom detection rules for Kerberos anomalies

### Remediation Tools
- **Group Policy**: Centralized Kerberos security configuration
- **PowerShell DSC**: Automated compliance enforcement
- **Third-Party PAM**: Privileged access management solutions

This comprehensive analysis of Kerberos attacks provides the foundation for understanding Purple Knight's highest-priority security category and implementing effective defenses against sophisticated authentication attacks.