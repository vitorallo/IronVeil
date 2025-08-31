# Consolidated Identity Security Indicators

This document provides a comprehensive and organized list of security indicators for both Active Directory (AD) and Microsoft Entra ID environments. These indicators represent common misconfigurations, vulnerabilities, and potential attack vectors that an identity security scanner should assess to provide a thorough security posture analysis.

Each indicator includes a unique reference ID, tier classification, description, significance, assessment methodology, and relevant references.

## Classification System

### Tier Structure
- **Tier 1 (Critical)**: Indicators that can lead to complete domain compromise (Weight: 9-10)
- **Tier 2 (High Impact)**: Indicators enabling privilege escalation and significant lateral movement (Weight: 7-8)  
- **Tier 3 (Medium Impact)**: Indicators that expand attack surface and enable initial access (Weight: 5-6)

### Reference ID Format
- **Active Directory**: `AD-T[Tier]-[Sequential Number]` (e.g., AD-T1-001)
- **Entra ID**: `EID-T[Tier]-[Sequential Number]` (e.g., EID-T1-001)

---

## Active Directory Security Indicators

### Tier 1: Critical - Domain Compromise Risks

#### AD-T1-001: Evidence of Mimikatz DCShadow Attack
* **Description:** DCShadow allows attackers to inject arbitrary changes into Active Directory by registering a "fake" domain controller and using normal AD replication to push malicious changes. This bypasses security event logging and can establish persistent backdoors.
* **Significance:** This is a highly stealthy and dangerous attack that can lead to complete domain compromise and persistent backdoor access, often bypassing traditional detection mechanisms.
* **Assessment:** Detection involves looking for unusual replication requests, temporary domain controller registrations, and unexpected schema modifications. Monitor AD replication metadata and event logs for anomalous activity.
* **References:** 
  * Semperis Blog: Purple Knight Community 5.0 Top Indicators

#### AD-T1-002: Well-known Privileged SIDs in SIDHistory
* **Description:** SID History injection involves adding privileged Security Identifiers (SIDs) to user objects' `SIDHistory` attribute, granting unauthorized elevated access without modifying group memberships.
* **Significance:** This technique allows attackers to maintain persistent Domain Admin privileges or achieve cross-domain privilege escalation while remaining stealthy, as it bypasses standard group membership auditing.
* **Assessment:** Identify unexpected privileged SIDs (e.g., Domain Admins, Enterprise Admins) in user `SIDHistory` attributes, especially cross-domain SID references. Enumerate `SIDHistory` for all user objects.
* **References:**
  * Semperis Blog: Purple Knight Community 5.0 Top Indicators

#### AD-T1-003: Zerologon Vulnerability (CVE-2020-1472)
* **Description:** A critical vulnerability in the Netlogon Remote Protocol (MS-NRPC) that allows an unauthenticated attacker to gain Domain Administrator privileges on a vulnerable domain controller.
* **Significance:** This vulnerability enables complete domain takeover and widespread compromise of the AD environment, making it one of the most severe AD vulnerabilities discovered.
* **Assessment:** Check for unpatched domain controllers and monitor for unusual Netlogon authentication failures. Verify patch levels and monitor network traffic for anomalous Netlogon activity.
* **References:**
  * Semperis Blog: Purple Knight Community 5.0 Top Indicators

#### AD-T1-004: KRBTGT Account with Resource-Based Constrained Delegation (RBCD)
* **Description:** When Resource-Based Constrained Delegation (RBCD) is configured on the `KRBTGT` account, it allows attackers to generate Ticket Granting Service (TGS) requests as any user, similar to Golden Ticket attacks.
* **Significance:** This is a critical Kerberos security misconfiguration that can lead to persistent domain compromise and impersonation of any domain user, potentially bypassing traditional Golden Ticket detection.
* **Assessment:** Check the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the `KRBTGT` account for any configured RBCD entries. Any such configuration should be flagged as critical.
* **References:**
  * Semperis Blog: Purple Knight Community 5.0 Top Indicators

#### AD-T1-005: Constrained Delegation to KRBTGT
* **Description:** Accounts configured for constrained delegation specifically to the `KRBTGT` service can abuse this trust relationship to obtain tickets for any user, effectively achieving Golden Ticket capabilities.
* **Significance:** This misconfiguration provides attackers with a powerful persistence mechanism and the ability to impersonate any user within the domain, leading to complete domain compromise.
* **Assessment:** Identify accounts that have constrained delegation configured to the `KRBTGT` service. Examine the `msDS-AllowedToDelegateTo` attribute for entries related to `KRBTGT`.
* **References:**
  * Semperis Blog: Purple Knight Community 5.0 Top Indicators

#### AD-T1-006: Unconstrained Delegation on Any Account
* **Description:** When a computer or user account is configured for unconstrained delegation, it can impersonate any user to any service on any server. This is a highly risky configuration that allows significant lateral movement.
* **Significance:** Unconstrained delegation is a critical security flaw that can lead to full domain compromise if an attacker gains control of a delegated account. It bypasses many security controls and allows for broad impersonation.
* **Assessment:** Identify all computer and user accounts with the `Trusted for Delegation` attribute enabled. Flag these accounts for immediate review and potential remediation.
* **References:**
  * HackTheBox Blog: 5 Active Directory misconfigurations (& how they're exploited)

### Tier 2: High Impact - Privilege Escalation Vectors

#### AD-T2-001: Weak or Misconfigured Access Control Lists (ACLs) with DCSync Rights
* **Description:** Improperly set permissions on AD objects that grant non-default principals DCSync rights, allowing replication of domain controller data including password hashes.
* **Significance:** Misconfigured ACLs with DCSync rights are a primary vector for privilege escalation and can lead to complete domain compromise through credential harvesting.
* **Assessment:** Enumerate ACLs on sensitive AD objects and identify any non-standard DCSync permissions granted to non-administrative users or groups. Check for `DS-Replication-Get-Changes*` extended rights.
* **References:**
  * Semperis Blog: 7 Active Directory Misconfigurations to Find and Fix—Now

#### AD-T2-002: Certificate Templates with Insecure Configurations
* **Description:** Misconfigured certificate templates can allow attackers to enroll for certificates that grant them elevated privileges or enable impersonation, including templates that allow requesters to specify a `subjectAltName`.
* **Significance:** Insecure certificate templates can be exploited for privilege escalation and bypassing authentication mechanisms through certificate-based attacks.
* **Assessment:** Analyze certificate templates for configurations that allow `subjectAltName` specification or have multiple insecure settings (weak cryptography, excessive validity periods, improper issuance requirements).
* **References:**
  * Semperis Blog: Purple Knight Introduces Entra ID Security Indicators

#### AD-T2-003: Print Spooler Enabled on Domain Controllers
* **Description:** The Print Spooler service, when enabled on Domain Controllers, exposes them to vulnerabilities like PrintNightmare (CVE-2021-34527, CVE-2021-1675) and facilitates coercion attacks for credential theft.
* **Significance:** This allows for privilege escalation and credential relay attacks against domain controllers, which can lead to full domain compromise.
* **Assessment:** Verify if the Print Spooler service is running on any domain controllers. Best practice is to disable this service on all DCs.
* **References:**
  * Semperis Blog: Purple Knight Community 5.0 Top Indicators

#### AD-T2-004: Reversible Passwords in Group Policy Objects
* **Description:** Group Policy Preferences (GPP) with stored passwords use a publicly known AES key for encryption, making all "Cpassword" entries easily decryptable by attackers.
* **Significance:** This misconfiguration allows attackers to harvest credentials in bulk from SYSVOL shares, leading to widespread service account compromise and lateral movement.
* **Assessment:** Scan GPO files (specifically `Groups.xml` and other preference files) within the SYSVOL share for the presence of "Cpassword" entries.
* **References:**
  * Semperis Blog: Purple Knight Community 5.0 Top Indicators

#### AD-T2-005: GPO Linking Delegation at Domain Level
* **Description:** Non-privileged users or groups with permissions to link Group Policy Objects (GPOs) at the domain level can deploy malicious policies across the entire domain.
* **Significance:** This misconfiguration allows for domain-wide malware deployment, privilege escalation through login scripts, and mass configuration manipulation, leading to widespread compromise.
* **Assessment:** Review GPO linking permissions at the domain level and restrict them to only authorized, privileged administrators.
* **References:**
  * Semperis Blog: Purple Knight Community 5.0 Top Indicators

#### AD-T2-006: Privileged Users with Service Principal Names (SPNs)
* **Description:** Privileged accounts that have Service Principal Names (SPNs) registered are vulnerable to Kerberoasting attacks, allowing offline password cracking of high-value targets.
* **Significance:** This allows attackers to obtain password hashes for high-value targets offline, enabling credential theft and privilege escalation against critical accounts.
* **Assessment:** Identify privileged user accounts with registered SPNs. Recommend removing SPNs from privileged accounts where possible or ensuring extremely strong, unique passwords.
* **References:**
  * Semperis Blog: Purple Knight Community 5.0 Top Indicators

#### AD-T2-007: Users with Kerberos Pre-Authentication Disabled
* **Description:** Accounts with Kerberos pre-authentication disabled are vulnerable to AS-REP Roasting attacks, allowing attackers to request a Ticket Granting Ticket (TGT) without providing a password.
* **Significance:** This enables offline password cracking of user accounts without prior authentication, providing an initial access vector for attackers.
* **Assessment:** Identify user accounts where the `Do not require Kerberos preauthentication` option is enabled. Recommend enabling pre-authentication for all accounts.
* **References:**
  * Semperis Blog: Purple Knight Community 5.0 Top Indicators

### Tier 3: Medium Impact - Attack Surface Expansion

#### AD-T3-001: Legacy Authentication Protocols Enabled
* **Description:** Older authentication protocols like NTLM are less secure than Kerberos and are vulnerable to relay attacks and brute-force attacks.
* **Significance:** Legacy authentication protocols provide an easier target for attackers due to their inherent weaknesses and lack of support for modern security features like MFA.
* **Assessment:** Check domain controller and critical server configurations for enabled NTLM authentication. Recommend disabling NTLM where possible and enforcing Kerberos.
* **References:**
  * Microsoft Learn: Best practices for securing Active Directory

#### AD-T3-002: Weak Password Policies
* **Description:** Lack of strong password policies (complexity, length, history) makes accounts susceptible to brute-force and dictionary attacks.
* **Significance:** Weak passwords are a fundamental security vulnerability, making accounts easy targets for compromise. Password reuse amplifies the impact of a single credential breach.
* **Assessment:** Evaluate the domain's password policy settings (minimum password length, complexity requirements, password history). Check for Fine-Grained Password Policy implementation.
* **References:**
  * Microsoft Learn: Best practices for securing Active Directory

#### AD-T3-003: Stale or Inactive Accounts
* **Description:** User and computer accounts that are no longer in use but remain active in AD pose a security risk as potential persistent access points.
* **Significance:** Stale accounts are often overlooked and can serve as backdoor access points for attackers, as they are less likely to be monitored or have their passwords changed.
* **Assessment:** Identify user accounts with no recent login activity using `lastLogonTimestamp` attribute. Flag disabled but not deleted accounts and computer accounts that have not authenticated recently.
* **References:**
  * Semperis Blog: 7 Active Directory Misconfigurations to Find and Fix—Now

#### AD-T3-004: LDAP Signing Not Required
* **Description:** If LDAP signing is not required on domain controllers, an attacker can perform an LDAP relay attack, intercepting and relaying authentication requests to gain unauthorized access.
* **Significance:** LDAP signing is a critical security measure to prevent tampering with LDAP traffic. Its absence allows for various relay attacks that can lead to domain compromise.
* **Assessment:** Verify that domain controllers are configured to require LDAP signing in domain controller security policies.
* **References:**
  * Microsoft Learn: Best practices for securing Active Directory

#### AD-T3-005: Built-in Operator Groups Not Empty
* **Description:** Built-in operator groups (Account Operators, Server Operators, Print Operators) have significant privileges. Non-empty groups expand the attack surface unnecessarily.
* **Significance:** These groups are often overlooked but can provide attackers with elevated privileges. Best practice dictates that they should be empty unless specific operational needs require otherwise.
* **Assessment:** Check the membership of built-in operator groups (Account Operators, Server Operators, Print Operators) and flag any non-empty groups for review.
* **References:**
  * Semperis Blog: 7 Active Directory Misconfigurations to Find and Fix—Now

---

## Entra ID Security Indicators

### Tier 1: Critical - Tenant Compromise Risks

#### EID-T1-001: Risky API Permissions Granted to Applications
* **Description:** Applications with excessive permissions like `RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`, or `Directory.ReadWrite.All` can escalate to Global Administrator privileges or access all tenant data.
* **Significance:** Over-privileged applications can be exploited for tenant-wide compromise, privilege escalation, and massive data exfiltration through legitimate API calls.
* **Assessment:** Enumerate application registrations and their granted Microsoft Graph API permissions. Flag applications with high-risk permissions that enable privilege escalation or broad data access.
* **References:**
  * AppGovScore Blog: Securing Microsoft Entra ID Applications

#### EID-T1-002: Cross-Environment Privileged Account Overlap
* **Description:** Accounts that hold high privileges in both Entra ID and on-premises Active Directory represent a critical security bridge between environments.
* **Significance:** This scenario creates a critical bridge for attackers to move between on-premises and cloud environments, making hybrid identity security a paramount concern.
* **Assessment:** Identify user accounts synchronized from on-premises AD that are members of highly privileged groups in both AD (Domain Admins) and Entra ID (Global Admins).
* **References:**
  * Semperis Blog: Purple Knight Introduces Entra ID Security Indicators

### Tier 2: High Impact - Privilege Escalation Vectors

#### EID-T2-001: Lack of Multi-Factor Authentication (MFA) for Privileged Accounts
* **Description:** Privileged accounts (Global Admins, User Administrators) without MFA are highly susceptible to credential theft and compromise.
* **Significance:** Compromise of privileged accounts without MFA can lead to complete control over the Entra ID tenant and connected resources. MFA is a fundamental security control for identity protection.
* **Assessment:** Identify privileged Entra ID roles assigned to users and verify if MFA is enforced for these accounts through Conditional Access policies or per-user settings.
* **References:**
  * Microsoft Learn: Best practices to secure with Microsoft Entra ID

#### EID-T2-002: Unrestricted User Consent for Applications
* **Description:** If unrestricted user consent is allowed, users can grant permissions to malicious applications to access company data on their behalf.
* **Significance:** Unrestricted user consent is a common phishing vector, allowing attackers to gain persistent access to user data and resources through seemingly legitimate applications.
* **Assessment:** Check Entra ID user consent settings to determine if users are allowed to consent to applications from unverified publishers without admin review.
* **References:**
  * Semperis Blog: Purple Knight Introduces Entra ID Security Indicators

#### EID-T2-003: Legacy Authentication Protocols Allowed
* **Description:** Legacy authentication protocols (POP3, IMAP, SMTP, older versions of Exchange ActiveSync) do not support MFA and are often used in password spray and brute-force attacks.
* **Significance:** Legacy authentication is a major attack vector for credential-based attacks, as it bypasses modern security controls like MFA and Conditional Access policies.
* **Assessment:** Verify Entra ID tenant settings and Conditional Access policies to ensure that legacy authentication protocols are blocked for all users.
* **References:**
  * Microsoft Learn: Best practices to secure with Microsoft Entra ID

#### EID-T2-004: Guest Accounts in Privileged Groups
* **Description:** Including external guest accounts in highly privileged Entra ID groups (Global Admins, Application Administrators) introduces unnecessary risk from external identity providers.
* **Significance:** Guest accounts in privileged roles expand the attack surface and can lead to unauthorized access if compromised, especially if external security controls are weaker.
* **Assessment:** Identify the membership of built-in or custom administrative roles and flag any guest accounts present in these groups.
* **References:**
  * Semperis Blog: Purple Knight Introduces Entra ID Security Indicators

### Tier 3: Medium Impact - Attack Surface Expansion

#### EID-T3-001: Administrative Units Not Being Used
* **Description:** Administrative Units (AUs) allow for granular delegation of administrative tasks within Entra ID. Without AUs, organizations often resort to granting broader, less secure permissions.
* **Significance:** Lack of AUs can lead to over-privileged administrators, increasing the risk of a breach. AUs enable a more secure, least-privilege approach to delegation.
* **Assessment:** For large or complex Entra ID environments, assess the presence and proper configuration of Administrative Units. Flag instances where Global Administrator roles are used for tasks that could be delegated with less privileged roles.
* **References:**
  * Semperis Blog: Purple Knight Introduces Entra ID Security Indicators

#### EID-T3-002: Security Defaults Not Enabled
* **Description:** Microsoft's Security Defaults provide a baseline level of security for Entra ID tenants by enforcing MFA for administrative roles, blocking legacy authentication, and requiring MFA for all users.
* **Significance:** Security Defaults offer a quick and effective way to implement essential security controls. Disabling them significantly weakens the overall security posture of the Entra ID tenant.
* **Assessment:** Verify that Security Defaults are enabled in the Entra ID tenant settings, unless replaced by equivalent Conditional Access policies.
* **References:**
  * Microsoft Learn: Best practices to secure with Microsoft Entra ID

#### EID-T3-003: Guests Having Permissions to Invite Other Guests
* **Description:** Allowing guest users to invite other guests can lead to uncontrolled proliferation of external accounts in the directory, making it difficult to manage and secure.
* **Significance:** Uncontrolled guest invitations can lead to an expanded attack surface and make it challenging to maintain a clear understanding of who has access to organizational resources.
* **Assessment:** Check external collaboration settings in Entra ID to determine if guests are allowed to invite other guests.
* **References:**
  * Semperis Blog: Purple Knight Introduces Entra ID Security Indicators

#### EID-T3-004: Non-Admin Users Can Register Applications
* **Description:** If non-administrative users can register applications, it opens a potential attack vector where malicious applications can be registered and used for data exfiltration.
* **Significance:** Allowing non-admins to register applications can lead to shadow IT and the introduction of malicious applications that can compromise data and user accounts.
* **Assessment:** Verify Entra ID user settings to determine if non-administrative users are allowed to register applications.
* **References:**
  * Semperis Blog: Purple Knight Introduces Entra ID Security Indicators

---

## Additional High-Value Indicators for Implementation

### Active Directory - Additional Considerations

#### AD-T2-008: Old KRBTGT Password
* **Description:** The `KRBTGT` account's password has not been rotated regularly. If the `KRBTGT` password hash is compromised, an old password enables longer-lasting Golden Ticket attacks.
* **Significance:** A stale `KRBTGT` password allows attackers to forge Golden Tickets that remain valid for extended periods, providing persistent domain access.
* **Assessment:** Check the `pwdLastSet` attribute for both `KRBTGT` account objects and ensure they have been rotated regularly (at least twice, with sufficient intervals).
* **References:**
  * Semperis Blog: Purple Knight Community 5.0 Top Indicators

#### AD-T3-006: Privileged Objects with Unprivileged Owners
* **Description:** Sensitive Active Directory objects (privileged groups, OUs) are owned by unprivileged accounts.
* **Significance:** This creates a privilege escalation path, as the unprivileged owner can modify permissions on the privileged object, potentially granting elevated access.
* **Assessment:** Identify privileged AD objects whose `Owner` attribute points to an unprivileged user or group. Recommend transferring ownership to appropriate, highly privileged accounts.
* **References:**
  * Semperis Blog: Purple Knight Community 5.0 Top Indicators

#### AD-T3-007: Machine Account Quota Greater Than Zero
* **Description:** The `ms-DS-MachineAccountQuota` attribute is set to a value greater than 0, allowing regular users to add computer accounts to the domain.
* **Significance:** This misconfiguration can be abused for various Kerberos attacks, including Resource-Based Constrained Delegation (RBCD) attacks and computer account takeovers.
* **Assessment:** Check the `ms-DS-MachineAccountQuota` attribute on the domain. Best practice is to set this value to 0 to prevent unauthorized computer account creation.
* **References:**
  * Semperis Blog: Purple Knight Community 5.0 Top Indicators

#### AD-T3-008: Resource-Based Constrained Delegation (RBCD) on Computer Objects
* **Description:** Resource-Based Constrained Delegation configured on computer objects can be abused for privilege escalation if attackers control the delegating account.
* **Significance:** While legitimate, if not properly managed, RBCD can be abused for privilege escalation, especially if attackers control the delegating account or target computer object.
* **Assessment:** Identify computer objects with RBCD configured through the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. Validate requirements and remove unnecessary configurations.
* **References:**
  * Semperis Blog: Purple Knight Community 5.0 Top Indicators

#### AD-T3-009: RC4 Encryption Type Supported by Domain Controllers
* **Description:** RC4 is a weaker encryption algorithm compared to AES. If domain controllers support RC4 for Kerberos, attackers can potentially downgrade to RC4 and exploit known vulnerabilities.
* **Significance:** Supporting weaker encryption algorithms increases the risk of successful attacks against Kerberos authentication, potentially leading to credential compromise.
* **Assessment:** Verify that domain controllers are configured to disallow RC4 encryption for Kerberos authentication.
* **References:**
  * Microsoft Learn: Best practices for securing Active Directory

#### AD-T3-010: Weak Certificate Cryptography
* **Description:** Certificates used within the AD environment that rely on weak key sizes (<2048 bits) or outdated algorithms like DSA are susceptible to cryptographic attacks.
* **Significance:** Compromised certificates can lead to system impersonation, authentication bypass, and compromise of the Public Key Infrastructure (PKI).
* **Assessment:** Scan for certificates with key sizes less than 2048 bits or those using DSA-based encryption. Flag these for revocation and reissuance with stronger cryptographic parameters.
* **References:**
  * Semperis Blog: Purple Knight Community 5.0 Top Indicators

#### AD-T3-011: Service Principal Name (SPN) Misconfigurations - General User Accounts
* **Description:** SPNs registered to regular user accounts (instead of computer accounts) with weak passwords enable Kerberoasting attacks for credential harvesting.
* **Significance:** Kerberoasting allows attackers to obtain service account password hashes without direct interaction with the service, making it a popular technique for lateral movement.
* **Assessment:** Scan for user accounts that have SPNs registered. For identified accounts, assess password strength requirements and flag accounts with potentially weak passwords.
* **References:**
  * Lepide Blog: Top 10 Active Directory Attack Methods

#### AD-T3-012: Privileged Account Management Issues
* **Description:** Privileged accounts with poor management practices such as `PasswordNotRequired`, `DontExpirePassword`, or being used for daily tasks significantly increase risk.
* **Significance:** Compromise of poorly managed privileged accounts can lead to complete control over the AD environment due to inadequate security controls.
* **Assessment:** Check for privileged accounts with `PasswordNotRequired` or `DontExpirePassword` enabled. Identify privileged accounts that are active but have not been used appropriately.
* **References:**
  * Microsoft Learn: Best practices for securing Active Directory

#### AD-T3-013: Misconfigured Group Policy Objects - General Security Settings
* **Description:** GPOs with misconfigurations that weaken security, such as insecure local administrator passwords, disabled firewalls, or weak auditing policies.
* **Significance:** GPOs are powerful tools for enforcing security, but misconfigurations can inadvertently weaken the security posture across the entire domain.
* **Assessment:** Analyze GPO settings for configurations that allow unprivileged users to modify security-sensitive settings or fail to enforce security best practices.
* **References:**
  * Semperis Blog: 7 Active Directory Misconfigurations to Find and Fix—Now

#### AD-T3-014: AdminSDHolder Object Permission Changes
* **Description:** The `AdminSDHolder` object controls the security template for all privileged accounts. Modifications to its ACL can weaken security for all administrative users and groups.
* **Significance:** Unauthorized changes to `AdminSDHolder` can lead to persistent backdoor access to privileged accounts, weakening their security and potentially enabling mass privilege escalation.
* **Assessment:** Monitor for unauthorized ACL modifications or new permissions on the `AdminSDHolder` object. Any changes should be immediately investigated and remediated.
* **References:**
  * Semperis Blog: Purple Knight Community 5.0 Top Indicators

---

## Implementation Priority for Development

### Phase 1: Critical Indicators (Tier 1)
Focus on the 8 most critical indicators that can lead to immediate domain compromise:
- All AD Tier 1 indicators (AD-T1-001 through AD-T1-006)
- All EID Tier 1 indicators (EID-T1-001 through EID-T1-002)

### Phase 2: High Impact Indicators (Tier 2)
Implement privilege escalation detection:
- AD Tier 2 indicators (AD-T2-001 through AD-T2-007)
- EID Tier 2 indicators (EID-T2-001 through EID-T2-004)

### Phase 3: Attack Surface Indicators (Tier 3)
Complete the assessment with attack surface expansion checks:
- AD Tier 3 indicators (AD-T3-001 through AD-T3-014)
- EID Tier 3 indicators (EID-T3-001 through EID-T3-004)

## References

1. Semperis Blog: 7 Active Directory Misconfigurations to Find and Fix—Now. URL: https://www.semperis.com/blog/7-active-directory-misconfigurations-to-find-and-fix-now/
2. HackTheBox Blog: 5 Active Directory misconfigurations (& how they're exploited). URL: https://www.hackthebox.com/blog/active-directory-misconfigurations
3. Lepide Blog: Top 10 Active Directory Attack Methods. URL: https://www.lepide.com/blog/top-10-active-directory-attack-methods/
4. Microsoft Learn: Best practices for securing Active Directory. URL: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory
5. Semperis Blog: Purple Knight Introduces Entra ID Security Indicators. URL: https://www.semperis.com/blog/purple-knight-azure-security-indicators/
6. Microsoft Learn: Best practices to secure with Microsoft Entra ID. URL: https://learn.microsoft.com/en-us/entra/architecture/secure-best-practices
7. AppGovScore Blog: Securing Microsoft Entra ID Applications: Addressing the Threat of Misconfigured Permissions. URL: https://www.appgovscore.com/blog/securing-microsoft-entra-id-applications-addressing-the-threat-of-misconfigured-permissions