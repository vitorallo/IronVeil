# IronVeil Desktop Scanner

## Overview
The IronVeil Desktop Scanner is a Windows application that performs security assessments on Active Directory and Microsoft Entra ID environments. It executes PowerShell-based security rules locally and uploads results to the IronVeil cloud platform for analysis and visualization.

## Architecture
- **Framework**: .NET 8 WPF
- **PowerShell Engine**: System.Management.Automation
- **Authentication**: OAuth 2.0 PKCE
- **API Communication**: HTTPS with retry logic and offline queue

## Project Structure
```
desktop-scanner/
├── IronVeil.sln              # Solution file
├── IronVeil.Desktop/          # WPF application
├── IronVeil.Core/             # Core business logic
├── IronVeil.PowerShell/       # PowerShell execution engine
└── IronVeil.Tests/            # Unit tests
```

## Prerequisites
- Windows 10/11
- .NET 8 SDK
- PowerShell 5.1 or higher
- Active Directory module (for AD scanning)
- Microsoft Graph SDK (for Entra ID scanning)

## Building
```bash
cd desktop-scanner
dotnet restore
dotnet build
```

## Running
```bash
dotnet run --project IronVeil.Desktop
```

Or run the executable directly:
```
IronVeil.Desktop\bin\Debug\net8.0-windows\IronVeil.Desktop.exe
```

## Features
- **Backend Selection**: Choose between community and enterprise backends
- **OAuth Authentication**: Secure login with token management
- **Scan Configuration**: Select AD, Entra ID, or hybrid scanning
- **PowerShell Rule Engine**: Execute security rules from `/indicators` folder
- **Progress Tracking**: Real-time scan progress updates
- **Results Display**: Severity-based findings visualization
- **Export Functionality**: Save results as JSON for upload
- **Auto-Upload**: Automatic result submission to cloud backend

## Development
The desktop scanner is designed to work independently from the cloud backend, with offline capabilities and queuing for when the backend is unavailable.

### Key Components
- **AuthenticationService**: OAuth 2.0 PKCE implementation
- **PowerShellExecutor**: Parallel rule execution with timeout management
- **ApiClient**: Secure API communication with retry logic
- **ConfigurationService**: Secure settings storage using AES encryption

## Testing
```bash
dotnet test
```

## Security
- Credentials are encrypted using AES-256
- OAuth tokens are stored securely
- PowerShell execution is sandboxed with timeouts
- All API communication uses HTTPS