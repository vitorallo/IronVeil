# Product Requirements Document: IronVeil an Identity Security Scanner

## 1. Introduction

### 1.1 Purpose
This Product Requirements Document (PRD) outlines the features, functionalities, and technical requirements for IronVeil, an Identity Security Scanner application. The primary goal of this application is to identify and assess common identity security misconfigurations and threats within both on-premises Active Directory (AD) and Microsoft Entra ID (formerly Azure AD) environments. By providing a comprehensive assessment, the scanner will enable organizations to proactively address vulnerabilities, reduce their attack surface, and enhance their overall identity security posture.

### 1.2 Scope
The Identity Security Scanner will focus on auditing and reporting capabilities for Active Directory and Entra ID. It will identify Indicators of Exposure (IoEs) and Indicators of Compromise (IoCs) related to identity-based attacks. The initial release will prioritize assessment and reporting, with future considerations for automated remediation. The application will provide detailed explanations of identified issues, their significance, and actionable recommendations for remediation.

## 2. Features

### 2.1 Core Scanning Capabilities

The Identity Security Scanner will incorporate robust scanning capabilities for both Active Directory and Entra ID environments. These capabilities are designed to detect a wide range of security misconfigurations, vulnerabilities, and potential indicators of compromise.

The full list of selected controls, or indicators to develop is in the file @Identity Security Indicatos (checks).md in this folder.

*   **Active Directory Assessment:** The scanner will perform a comprehensive audit of on-premises Active Directory environments to identify common misconfigurations and vulnerabilities. This includes, but is not limited to, checks for:
    *   Weak or misconfigured Access Control Lists (ACLs) and permissions on sensitive AD objects.
    *   Accounts configured for unconstrained delegation.
    *   Service Principal Name (SPN) misconfigurations susceptible to Kerberoasting.
    *   Enabled legacy authentication protocols (e.g., NTLM).
    *   Weak password policies or evidence of password reuse.
    *   Stale or inactive user and computer accounts.
    *   Privileged accounts with excessive permissions or poor management practices (e.g., `PasswordNotRequired`, `DontExpirePassword` enabled).
    *   Misconfigured Group Policy Objects (GPOs), including those not enforcing Fine-Grained Password Policies (FGPP).
    *   LDAP signing not being required on domain controllers.
    *   Non-empty built-in operator groups.
    *   Domain controllers supporting RC4 encryption type for Kerberos.
    *   Insecure certificate templates allowing `subjectAltName` specification or having multiple insecure configurations.

*   **Entra ID (Azure AD) Assessment:** The scanner will extend its capabilities to Microsoft Entra ID, focusing on cloud-specific security indicators. This will include checks for:
    *   Lack of Multi-Factor Authentication (MFA) enforcement for privileged accounts.
    *   Unrestricted user consent settings for applications.
    *   Risky API permissions granted to application service principals.
    *   Allowed legacy authentication protocols.
    *   Privileged groups containing guest accounts.
    *   Underutilization of Administrative Units for delegated administration.
    *   Security Defaults not being enabled.
    *   Guest users having permissions to invite other guests.
    *   AAD privileged users also holding privileges in on-premises AD (hybrid identity risk).
    *   Non-administrative users being able to register custom applications.

*   **Hybrid Identity Correlation:** The scanner will correlate findings between on-premises AD and Entra ID to identify hybrid identity risks, such as accounts privileged in both environments, which can facilitate lateral movement between cloud and on-premises infrastructures.

*   **Indicator of Exposure (IoE) or Identity Attack Surface and Indicator of Compromise (IoC) Detection:** The scanner will differentiate between IoEs (risky configurations that can be exploited) and IoCs (evidence of an ongoing or past compromise) to provide a clear understanding of the security posture and potential threats. 

#### 2.1.2 Goal
the goal of IronVeil is to provide an overview of the Identity Attack Surface, via a dashboard or to export the dashboard content to a comphrensive JSON file to be imported somewhere else. APIs will be later implemented to allow also a API based lookup of info only for the web app, not for the standalone windows version. 

### 2.2 Reporting and Visualization, Identity Attack Surface

The application will provide comprehensive and actionable reporting capabilities to help users understand their security posture and prioritize remediation efforts.

*   **Security Scorecard:** A high-level overview providing an overall security score, broken down by category (e.g., AD, Entra ID, Privileged Access, Account Hygiene).
*   **Detailed Findings Report:** A granular report listing all identified misconfigurations and vulnerabilities, including:
    *   **Issue Description:** Clear explanation of the security issue.
    *   **Severity Level:** Categorization of the issue based on its potential impact (e.g., Critical, High, Medium, Low).
    *   **Affected Entities:** Specific users, groups, computers, or applications impacted by the issue.
    *   **Remediation Guidance:** Prescriptive, step-by-step instructions for how to fix each identified issue, including best practices and links to relevant Microsoft documentation or security advisories.
    *   **References:** Citations to official documentation, security research, or industry best practices supporting the finding.
*   **Trend Analysis:** Ability to track security posture over time, showing improvements or degradations based on periodic scans.
*   **Export Options:** Support for exporting reports in various formats (e.g., PDF, CSV, JSON) for further analysis or integration with other security tools.
*   **Interactive Dashboard:** A user-friendly graphical interface providing visualizations of security posture, top risks, and remediation progress.

### 2.3 Integration

To enhance usability and integrate with existing security workflows, the scanner will consider the following integration points:

*   **Microsoft Graph API:** For seamless and secure interaction with Microsoft Entra ID.
*   **PowerShell:** Utilization of PowerShell cmdlets for Active Directory queries and potential automation of certain assessment tasks.
*   **Ticketing Systems (Future):** Integration with IT service management or ticketing systems to automatically create remediation tasks based on scan findings.




## 3. Security Indicators (Detailed List)

This section provides a comprehensive list of security indicators that the Identity Security Scanner will assess. These indicators are categorized by environment (Active Directory and Entra ID) and include detailed descriptions, their significance, assessment methods, and relevant references. This forms the technical backbone of the scanner's detection capabilities.

import the list, consider the file @"Identity Security Indicators(checks).md" in this folder


## 4. User Stories

User stories describe the functionality of the Identity Security Scanner from the perspective of different user roles. These stories will guide the development process and ensure the application meets the needs of its intended users.

### 4.1 Administrator User Stories

*   **As an Identity Security Administrator,** I want to scan my on-premises Active Directory environment for common misconfigurations so that I can identify and remediate potential security risks.
*   **As an Identity Security Administrator,** I want to scan my Microsoft Entra ID tenant for security vulnerabilities so that I can ensure compliance and protect cloud identities.
*   **As an Identity Security Administrator,** I want to view a consolidated report of all identified security issues across both AD and Entra ID so that I can understand my hybrid identity security posture at a glance.
*   **As an Identity Security Administrator,** I want to see the severity level of each identified issue so that I can prioritize my remediation efforts.
*   **As an Identity Security Administrator,** I want to receive detailed remediation guidance for each security finding so that I can efficiently fix the issues.
*   **As an Identity Security Administrator,** I want to track my security posture over time to demonstrate improvements and measure the effectiveness of my security initiatives.
*   **As an Identity Security Administrator,** I want to export scan reports in various formats (e.g., PDF, CSV) so that I can share them with stakeholders or integrate them with other tools.
*   **As an Identity Security Administrator,** I want to identify privileged accounts that lack Multi-Factor Authentication (MFA) in Entra ID so that I can enforce stronger authentication for critical roles.
*   **As an Identity Security Administrator,** I want to detect instances of unrestricted user consent for applications in Entra ID so that I can prevent malicious applications from gaining unauthorized access.
*   **As an Identity Security Administrator,** I want to find stale or inactive accounts in Active Directory so that I can disable or remove them to reduce the attack surface.

### 4.2 Auditor User Stories

*   **As a Security Auditor,** I want to generate a comprehensive report of identity security configurations to demonstrate compliance with internal policies and external regulations.
*   **As a Security Auditor,** I want to verify that security best practices are being followed in both Active Directory and Entra ID environments.
*   **As a Security Auditor,** I want to see clear references and explanations for each security indicator to understand the rationale behind the findings.

### 4.3 Management User Stories

*   **As a Security Manager,** I want a high-level security scorecard to quickly understand the overall identity security health of my organization.
*   **As a Security Manager,** I want to see trends in our security posture to assess the effectiveness of our security team and investments.
*   **As a Security Manager,** I want to understand the potential impact of identified vulnerabilities to make informed decisions about resource allocation for remediation.

### 4.4 External partners

*   **As a external partner, ASM web application,** I want to be able to import a high-level security scorecard to quickly understand the overall identity security health of the scanned organisation and producte a dashboard on my own.
*   **As a external partner, ASM web application,** I want to be able, eventually non offline, to query the information via APIs
*   **As a external partner, ASM web application,** I want to make sure to match the scan performed to the proper client, target in my Attack Surface Management app.


## 5. Technical Requirements

This section outlines the technical requirements for the Identity Security Scanner, covering aspects such as performance, scalability, security, and deployment.

### 5.1 Performance
*   **Scan Speed:** The scanner should be able to complete a comprehensive scan of a medium-sized Active Directory environment (e.g., 10,000 users, 5,000 computers) and an Entra ID tenant within a reasonable timeframe (e.g., under 30 minutes for a full scan, under 5 minutes for a quick scan of critical indicators).
*   **Resource Utilization:** The scanner should be optimized for minimal impact on the performance of domain controllers, Entra ID services, and the host machine where it is executed.

### 5.2 Scalability
*   **Environment Size:** The scanner should be capable of assessing environments ranging from small businesses to large enterprises with tens of thousands of users and objects.
*   **Modular Design:** The architecture should support the addition of new security indicators and assessment modules for other identity platforms (e.g., Okta, Google Workspace) in future releases without requiring significant re-architecture.

### 5.3 Security
*   **Least Privilege:** The scanner should operate with the principle of least privilege, requiring only the necessary permissions to perform its assessments in both AD and Entra ID.
*   **Secure Data Handling:** All collected data, especially sensitive configuration information, should be handled securely, encrypted in transit and at rest, and purged after report generation or as per data retention policies.
*   **Authentication:** The scanner will utilize secure authentication mechanisms for connecting to Active Directory (e.g., Kerberos, NTLM with strong credentials) and Entra ID (e.g., OAuth 2.0, service principal with certificate-based authentication).
*   **Code Security:** The application code will adhere to secure coding practices, be regularly reviewed for vulnerabilities, and utilize secure libraries and frameworks.

### 5.4 Deployment and Compatibility
*   **Operating System:** The scanner should be compatible with common Windows Server operating systems for on-premises AD scanning (e.g., Windows Server 2016, 2019, 2022) and run on standard client operating systems (e.g., Windows 10/11) for local execution.
*   **Dependencies:** All necessary runtime dependencies (e.g., .NET Framework, PowerShell modules) should be clearly documented and easily installable.
*   **Installation:** Provide a straightforward installation process, ideally a single executable or a simple script-based deployment.

### 5.5 User Interface (UI) / User Experience (UX)
*   **Intuitive Design:** The UI should be intuitive and easy to navigate, allowing users to initiate scans, view reports, and access remediation guidance with minimal training or optionally with a direct commandline headless command, to produce straight the JSON report to be imported by a partner. 
*   **Clear Visualizations:** Reports and dashboards should use clear and concise visualizations to present complex security data effectively.
*   **Accessibility:** Adhere to standard accessibility guidelines to ensure usability for a broad range of users.


## 6. Architecture Considerations

The proposed architecture for the Identity Security Scanner aims for modularity, extensibility, and efficiency to support comprehensive assessments of both Active Directory and Entra ID environments.

### 6.1 Core Components

*   **Scan Engine:** The central component responsible for executing assessment logic. It will orchestrate data collection from AD and Entra ID, apply security indicator checks, and generate raw findings.
*   **Data Collection Modules:**
    *   **Active Directory Collector:** Utilizes LDAP queries, PowerShell cmdlets (e.g., `ActiveDirectory` module), and potentially WMI to gather configuration data, object attributes, and security settings from domain controllers.
    *   **Entra ID Collector:** Leverages Microsoft Graph API calls and potentially Azure AD PowerShell cmdlets (e.g., `AzureAD` or `Az.Accounts` modules) to retrieve tenant configurations, user and group properties, application registrations, and Conditional Access policies. Provide information on how to configure also the Azure side of the requirements.
*   **Security Analyzer:** Processes the collected data against a predefined set of security indicators (rules) that are going to be developed by the rules-agent and in the folder /indicators. Each indicator will have specific logic to identify misconfigurations or vulnerabilities. This component will categorize findings by severity and type (IoE/IoC).
*   **Reporting Module:** Generates human-readable reports (PDF, HTML) and machine-readable outputs (CSV, JSON) based on the analyzed findings. It will include summary scorecards, detailed issue descriptions, and remediation guidance.
*   **User Interface (UI):** A graphical interface for initiating scans, configuring settings, viewing real-time progress, and presenting scan results through dashboards and detailed reports. EVERYTHING MUST BE SUPER SIMPLE

### 6.2 Data Flow

1.  **Initiation:** User initiates a scan via the UI, specifying target environments (AD, Entra ID, or both). Usually it's the local environemnt where the scanner was executed. Execution is with local user rights.
2.  **Authentication:** The scanner authenticates to AD (e.g., with provided credentials or local credetials from the user who is running the tool on local windows) and Entra ID (e.g., via OAuth 2.0 and service principal).
3.  **Data Collection:** Data Collection Modules query the respective identity sources (AD domain controllers, Microsoft Graph API endpoints) to gather necessary configuration and object data.
4.  **Data Processing:** Collected data is fed into the Security Analyzer, which applies predefined rules to identify security issues.
5.  **Reporting:** The Reporting Module aggregates and formats the findings into comprehensive reports and populates the UI dashboard.

### 6.3 Extensibility

*   **Rule-Based Engine:** The Security Analyzer should be designed with a flexible rule engine, allowing for easy addition or modification of security indicators without requiring core code changes. This could involve external configuration files or a scripting language for defining new checks.
*   **Modular Collectors:** New data collection modules can be added to support additional identity platforms (e.g., Okta, Google Workspace) or specialized data sources in the future.
*   **API-First Design:** Exposing core scanning and reporting functionalities via an API would enable integration with other security tools and automation platforms.

### 6.4 Deployment Model

*   **IronVeil Standalone Desktop Application/Scanner:** For initial release, a standalone application (e.g., Windows executable) that can be run on a workstation or server within the customer's network. This minimizes deployment complexity and addresses on-premises AD scanning requirements.
*   **Hybrid Cloud Model (Future):** For larger enterprises, consider a hybrid model where a lightweight agent or connector runs on-premises for AD data collection, sending findings securely to a cloud-based analysis and reporting platform. API should for partners should be developed only here.

### 6.5 Technology stack
Since we’re starting with the desktop app (standalone Windows scanner) and later evolving to a web app (with APIs and partner integrations), here’s a recommended technology stack strategy tailored to your product:

#### 6.5.1 Desktop Application (First Release – Windows Standalone Scanner)

Goals:
	•	Runs locally on Windows 10/11 or Windows Server.
	•	Needs access to Active Directory (LDAP, PowerShell) and Entra ID (Microsoft Graph API).
	•	Produces reports (JSON, PDF, CSV) and has a simple UI + optional CLI.
	•	Lightweight, easy to install, preferably a single executable.

Recommended Tech Stack:
	•	Core Language:
	•	C# (.NET 8 / .NET 6 LTS) → best fit for Windows environment:
	•	Native access to Active Directory via System.DirectoryServices.
	•	First-class support for PowerShell automation.
	•	Great libraries for Microsoft Graph API.
	•	Easy to package as a single .exe with dotnet publish -r win-x64 --self-contained.
	•	UI Options:
	•	WPF (Windows Presentation Foundation) → if you want a modern, desktop-only GUI.
	•	Reporting & Visualization:
	•	FastReport or QuestPDF for PDF generation.
	•	OxyPlot / LiveCharts for dashboard-style charts.
	•	CLI Support:
	•	.NET System.CommandLine → for headless execution that outputs JSON (for partner import).
	•	Packaging:
	•	Single-file .exe using .NET Publish or MSIX installer for enterprise-friendly deployment.

👉 This stack makes the scanner native, fast, and tightly integrated with Windows/AD, which is crucial for your use case. Security checks, or scripts or indicators are all written in powershell and used by the UI.

⸻

🔹 Web Application (Later Phase – Partner/Enterprise Edition)

Goals from PRD:
	•	API-based lookup of results.
	•	Cloud dashboard (multi-tenant).
	•	Imports JSON results from desktop tool.
	•	Future support for continuous monitoring, ticketing system integrations, etc.

Recommended Tech Stack:
	•	Backend API:
	•	Node.js (NestJS) 
	•	If dev team is already deep or it's better to integrate a light agent setup in .NET from desktop → stick with ASP.NET Core.
	•	If you want flexibility and frontend/backend separation → NestJS is a great choice.
	•	Frontend (Dashboard):
	•	React (Next.js) → SEO-friendly, modular, great for dashboards.
	•	UI components: TailwindCSS + shadcn/ui (fast dev & clean design).
	•	Graphing: Recharts / Chart.js / D3.js.
	•	Database:
	•	PostgreSQL (preferred) 
	•	Auth & Security:
	•	OAuth2 / OpenID Connect (integration with Entra ID possible).
	•	JWT-based sessions for API clients.
	•	Infrastructure:
	•	Containerized with Docker + Kubernetes (for scaling).
	•	CI/CD via GitHub Actions.


## 7. Future Enhancements only for the enterprise app

This section outlines potential future enhancements for the Identity Security Scanner, which can be considered for subsequent releases based on user feedback, market demand, and evolving threat landscapes.

*   **Automated Remediation Suggestions:** Beyond providing guidance, offer the option for automated or semi-automated remediation of identified misconfigurations (with appropriate safeguards and user approval).
*   **Continuous Monitoring:** Implement a continuous monitoring capability to detect changes in identity configurations in real-time and alert on new vulnerabilities or misconfigurations.
*   **Threat Intelligence Integration:** Integrate with external threat intelligence feeds to enrich findings with context on active exploits or emerging attack techniques targeting specific misconfigurations.
*   **Behavioral Analytics:** Incorporate user and entity behavioral analytics (UEBA) to detect anomalous activities that might indicate a compromise, even if configurations appear secure.
*   **Support for Other Identity Providers:** Extend scanning capabilities to other identity platforms such as Okta, Google Workspace, or other SAML/OAuth providers.
*   **Cloud-Native Deployment:** Offer a cloud-native version of the scanner for organizations operating entirely in the cloud, leveraging serverless functions and managed services.
*   **API for External Integration:** Provide a well-documented API for seamless integration with other security tools, DevOps pipelines, and custom automation scripts.

## 8. Appendix

### 8.1 References

*   [1] Semperis Blog: 7 Active Directory Misconfigurations to Find and Fix—Now. URL: `https://www.semperis.com/blog/7-active-directory-misconfigurations-to-find-and-fix-now/`
*   [2] HackTheBox Blog: 5 Active Directory misconfigurations (& how they're exploited). URL: `https://www.hackthebox.com/blog/active-directory-misconfigurations`
*   [3] Lepide Blog: Top 10 Active Directory Attack Methods. URL: `https://www.lepide.com/blog/top-10-active-directory-attack-methods/`
*   [4] Microsoft Learn: Best practices for securing Active Directory. URL: `https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory`
*   [5] Semperis Blog: Purple Knight Introduces Entra ID (formerly Azure AD) Security Indicators. URL: `https://www.semperis.com/blog/purple-knight-azure-security-indicators/`
*   [6] Microsoft Learn: Best practices to secure with Microsoft Entra ID. URL: `https://learn.microsoft.com/en-us/entra/architecture/secure-best-practices`
*   [7] AppGovScore Blog: Securing Microsoft Entra ID Applications: Addressing the Threat of Misconfigured Permissions. URL: `https://www.appgovscore.com/blog/securing-microsoft-entra-id-applications-addressing-the-threat-of-misconfigured-permissions`


### 8.1 References

*   [1] Semperis Blog: 7 Active Directory Misconfigurations to Find and Fix—Now. URL: `https://www.semperis.com/blog/7-active-directory-misconfigurations-to-find-and-fix-now/`
*   [2] HackTheBox Blog: 5 Active Directory misconfigurations (& how they're exploited). URL: `https://www.hackthebox.com/blog/active-directory-misconfigurations`
*   [3] Lepide Blog: Top 10 Active Directory Attack Methods. URL: `https://www.lepide.com/blog/top-10-active-directory-attack-methods/`
*   [4] Microsoft Learn: Best practices for securing Active Directory. URL: `https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory`
*   [5] Semperis Blog: Purple Knight Introduces Entra ID (formerly Azure AD) Security Indicators. URL: `https://www.semperis.com/blog/purple-knight-azure-security-indicators/`
*   [6] Microsoft Learn: Best practices to secure with Microsoft Entra ID. URL: `https://learn.microsoft.com/en-us/entra/architecture/secure-best-practices`
*   [7] AppGovScore Blog: Securing Microsoft Entra ID Applications: Addressing the Threat of Misconfigured Permissions. URL: `https://www.appgovscore.com/blog/securing-microsoft-entra-id-applications-addressing-the-threat-of-misconfigured-permissions`
*   [8] Semperis Blog: Purple Knight Community 5.0 Top Indicators. URL: `https://www.semperis.com/blog/purple-knight-azure-security-indicators/`

*   [8] Semperis Blog: Purple Knight Community 5.0 Top Indicators. URL: `https://www.semperis.com/blog/purple-knight-azure-security-indicators/`


