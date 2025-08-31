# Windows Development Environment Setup Guide - IronVeil

## Prerequisites - Fresh Windows 11 Installation

### 1. Enable Developer Mode
```powershell
# Run as Administrator
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Value 1
```

### 2. Install Windows Subsystem for Linux (Optional but Recommended)
```powershell
# Run as Administrator
wsl --install
# Restart required
```

## Core Development Tools

### 1. Install Git for Windows
```powershell
# Download and install from: https://git-scm.com/download/win
# Or via winget:
winget install --id Git.Git -e --source winget
```

### 2. Install Visual Studio 2022 Community (Recommended)
```powershell
# Download from: https://visualstudio.microsoft.com/vs/community/
# Or via winget:
winget install Microsoft.VisualStudio.2022.Community

# Required Workloads during installation:
# - .NET desktop development
# - Windows Application Packaging
```

**Visual Studio Components Needed:**
- .NET 8.0 SDK
- WPF project templates
- NuGet Package Manager
- Git integration
- PowerShell Tools for Visual Studio

### 3. Alternative: VS Code Setup
```powershell
# If you prefer VS Code over Visual Studio
winget install Microsoft.VisualStudioCode

# Extensions to install after VS Code starts:
# - C# Dev Kit (ms-dotnettools.csdevkit)
# - PowerShell (ms-vscode.powershell)
# - .NET Install Tool (ms-dotnettools.vscode-dotnet-runtime)
```

### 4. Install .NET 8 SDK (if not included with Visual Studio)
```powershell
# Download from: https://dotnet.microsoft.com/download/dotnet/8.0
# Or via winget:
winget install Microsoft.DotNet.SDK.8
```

Verify installation:
```powershell
dotnet --version
# Should show 8.x.x
```

### 5. Install PowerShell 7+ (Latest)
```powershell
# PowerShell 7 is more modern than Windows PowerShell 5.1
winget install --id Microsoft.PowerShell --source winget
```

### 6. Install GitHub CLI
```powershell
winget install --id GitHub.cli
```

After installation, authenticate:
```powershell
gh auth login
# Follow prompts to authenticate with your GitHub account
```

## Active Directory Development Tools

### 1. Install Remote Server Administration Tools (RSAT)
```powershell
# Run as Administrator - Required for AD PowerShell module
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online

# Specifically for Active Directory:
Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
```

### 2. Install Active Directory PowerShell Module
```powershell
# Usually comes with RSAT, verify installation:
Import-Module ActiveDirectory
Get-Module ActiveDirectory -ListAvailable
```

### 3. Install Azure AD/Entra ID PowerShell Modules
```powershell
# Install Microsoft Graph PowerShell SDK (recommended)
Install-Module Microsoft.Graph -Force -AllowClobber

# Install legacy Azure AD module (backup/compatibility)
Install-Module AzureAD -Force -AllowClobber

# Install Azure PowerShell module
Install-Module Az -Force -AllowClobber
```

## Development Environment Setup

### 1. Clone the IronVeil Repository
```powershell
# Navigate to your development directory
cd C:\Dev
# Or create it:
mkdir C:\Dev
cd C:\Dev

# Clone the repository


cd IronVeil
```

### 2. PowerShell Development Environment
```powershell
# Install PowerShell ISE (if not already installed)
# It comes with Windows, but verify:
powershell_ise.exe

# Or configure VS Code for PowerShell development
code --install-extension ms-vscode.powershell
```

### 3. Set PowerShell Execution Policy (Development)
```powershell
# Run as Administrator - Required for running our security scripts
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

# For current user (less privileged option):
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Project-Specific Setup

### 1. Create Solution Structure
```powershell
# Navigate to project directory
cd C:\Dev\IronVeil

# Create .NET solution (when ready to start coding)
dotnet new sln -n IronVeil

# Create WPF application project
dotnet new wpf -n IronVeil.Desktop -f net8.0-windows
dotnet sln add IronVeil.Desktop

# Create class library for core logic
dotnet new classlib -n IronVeil.Core -f net8.0
dotnet sln add IronVeil.Core

# Create test project
dotnet new mstest -n IronVeil.Tests -f net8.0
dotnet sln add IronVeil.Tests

# Add project references
dotnet add IronVeil.Desktop reference IronVeil.Core
dotnet add IronVeil.Tests reference IronVeil.Core
```

### 2. Install Required NuGet Packages
```powershell
# Core library packages
dotnet add IronVeil.Core package System.DirectoryServices
dotnet add IronVeil.Core package Microsoft.Graph
dotnet add IronVeil.Core package System.Management.Automation
dotnet add IronVeil.Core package QuestPDF
dotnet add IronVeil.Core package System.CommandLine

# Desktop application packages  
dotnet add IronVeil.Desktop package OxyPlot.Wpf
# Or alternative: dotnet add IronVeil.Desktop package LiveCharts.Wpf

# Test packages
dotnet add IronVeil.Tests package Microsoft.NET.Test.Sdk
dotnet add IronVeil.Tests package MSTest.TestAdapter
dotnet add IronVeil.Tests package MSTest.TestFramework
dotnet add IronVeil.Tests package Moq
```

### 3. Build and Verify Setup
```powershell
# Build the solution
dotnet build

# Run tests (once you have some)
dotnet test

# Run the desktop application
dotnet run --project IronVeil.Desktop
```

## Development Tools and Utilities

### 1. Install Additional Development Tools
```powershell
# JetBrains dotPeek (free .NET decompiler)
winget install JetBrains.dotPeek

# Sysinternals Suite (for AD debugging)
# Download from: https://docs.microsoft.com/sysinternals/
# Or install via Microsoft Store: "Sysinternals Suite"

# Process Monitor - useful for debugging file/registry access
# Included in Sysinternals Suite

# Windows SDK (for advanced WPF features)
winget install Microsoft.WindowsSDK
```

### 2. Configure Visual Studio for Active Directory Development
**Extensions to Install in Visual Studio:**
- PowerShell Tools for Visual Studio
- GitHub Extension for Visual Studio
- .NET Object Browser
- Productivity Power Tools

### 3. Active Directory Lab Environment Setup (Optional)
If you want to test against a local AD environment:

```powershell
# Install Hyper-V (requires Pro/Enterprise Windows)
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All

# Or use VirtualBox/VMware for domain controller VMs
```

## Security and Testing Setup

### 1. Configure Windows Defender Exclusions
```powershell
# Run as Administrator - Exclude development folders from scanning
Add-MpPreference -ExclusionPath "C:\Dev"
Add-MpPreference -ExclusionProcess "dotnet.exe"
Add-MpPreference -ExclusionProcess "powershell.exe"
Add-MpPreference -ExclusionProcess "devenv.exe"
```

### 2. Configure PowerShell for Security Development
```powershell
# Enable PowerShell script block logging (for debugging)
# Run as Administrator
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force }
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1
```

### 3. Install Testing Utilities
```powershell
# Pester (PowerShell testing framework)
Install-Module -Name Pester -Force -SkipPublisherCheck

# PSScriptAnalyzer (PowerShell static analysis)
Install-Module -Name PSScriptAnalyzer -Force
```

## Environment Verification

### 1. Verify All Installations
```powershell
# Check .NET
dotnet --version

# Check PowerShell modules
Get-Module -ListAvailable | Where-Object {$_.Name -match "ActiveDirectory|Microsoft.Graph|AzureAD"}

# Check Git
git --version

# Check GitHub CLI
gh --version

# Test PowerShell execution
Get-ExecutionPolicy
```

### 2. Test Active Directory Connectivity (if domain-joined)
```powershell
# Test AD connectivity
Get-ADDomain
Get-ADForest

# Test Graph API setup (requires authentication)
Connect-MgGraph -Scopes "Directory.Read.All"
Get-MgUser -Top 5
```

## Final Development Setup

### 1. Open Project in Visual Studio
```powershell
# Open solution in Visual Studio
cd C:\Dev\IronVeil
start IronVeil.sln

# Or open in VS Code
code .
```

### 2. Configure Debugging
- Set IronVeil.Desktop as startup project
- Configure mixed-mode debugging for PowerShell integration
- Set up breakpoints for both C# and PowerShell code

### 3. Initial Development Test
```powershell
# Test basic functionality
dotnet build
dotnet run --project IronVeil.Desktop

# Test PowerShell rule execution framework
# (This will be developed as part of the project)
```

## Troubleshooting Common Issues

### PowerShell Module Issues
```powershell
# If modules don't install/import properly
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Update-Help -Force -ErrorAction SilentlyContinue
```

### .NET SDK Issues
```powershell
# List installed SDKs
dotnet --list-sdks

# Clear NuGet cache if package restore fails
dotnet nuget locals all --clear
```

### Active Directory Access Issues
```powershell
# Test domain connectivity
Test-ComputerSecureChannel -Verbose

# Check current user's AD permissions
whoami /groups
```

## Next Steps

1. **Move to Windows 11** system
2. **Follow this setup guide** step by step
3. **Clone the repository** from GitHub
4. **Begin development** using the specialized subagents:
   - Use **powershell-security-rules-developer** for creating security rules
   - Use **desktop-gui-developer** for WPF application development
5. **Follow TASKS.md** for structured development phases

## Support Resources

- **Active Directory Cmdlets**: `Get-Help Get-AD* -Examples`
- **Microsoft Graph Documentation**: https://docs.microsoft.com/graph/
- **WPF Documentation**: https://docs.microsoft.com/dotnet/desktop/wpf/
- **PowerShell Documentation**: https://docs.microsoft.com/powershell/

The environment will be ready for full IronVeil development with complete Active Directory and Entra ID integration capabilities.