# Entra ID Authentication Integration Guide for IronVeil Desktop Application

**Document**: Entra ID Desktop Authentication Integration Guide  
**Date**: September 1, 2025  
**Status**: 🟡 PARTIALLY IMPLEMENTED  
**Purpose**: Clear explanation of Entra ID authentication architecture and integration requirements  

## Executive Summary

This document provides a comprehensive guide on how Entra ID (Azure AD) authentication is integrated into the IronVeil desktop application. While the PowerShell rules and authentication helper are **fully implemented**, the desktop application integration requires additional work to connect these components.

## Current Implementation Status

### ✅ What's Completed

1. **PowerShell Security Rules** (16 EID-T* rules)
   - All Entra ID security assessment rules are complete
   - Each rule checks for Microsoft Graph connection
   - Standardized JSON output format ready for desktop consumption

2. **Authentication Helper Script** (`IronVeil-ConnectEntraID.ps1`)
   - Simplifies Microsoft Graph authentication
   - Consolidates all required permissions
   - Provides connection testing functionality

3. **Desktop Application Foundation** 
   - WPF application framework exists
   - PowerShell execution engine implemented
   - API upload capability to cloud backend

### 🟡 What Needs Integration

The desktop application needs to bridge the authentication helper with the EID rules execution.

## Authentication Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    IronVeil Desktop App                      │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  1. User clicks "Run Entra ID Scan"                          │
│                    ↓                                          │
│  2. App executes IronVeil-ConnectEntraID.ps1                 │
│                    ↓                                          │
│  3. Browser opens for Microsoft Graph authentication         │
│     (User signs in with admin account)                       │
│                    ↓                                          │
│  4. Authentication token stored in PowerShell session        │
│                    ↓                                          │
│  5. App executes EID-T* rules in authenticated context       │
│                    ↓                                          │
│  6. JSON results collected and uploaded to cloud             │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Requirements

### Desktop Application Changes Needed

#### 1. Add Entra ID Authentication UI Elements

```csharp
// In MainWindow.xaml
<StackPanel x:Name="EntraIDPanel">
    <TextBlock Text="Entra ID Authentication" FontWeight="Bold"/>
    <Button x:Name="ConnectEntraIDButton" 
            Content="Connect to Entra ID" 
            Click="ConnectEntraID_Click"/>
    <TextBlock x:Name="EntraIDStatusText" 
               Text="Not connected" 
               Foreground="Gray"/>
    <CheckBox x:Name="IncludeEntraIDRules" 
              Content="Include Entra ID security checks"/>
</StackPanel>
```

#### 2. Implement Authentication Handler

```csharp
// In MainWindow.xaml.cs or EntraIDAuthenticationManager.cs
public class EntraIDAuthenticationManager
{
    private PowerShell _powerShell;
    private bool _isConnected = false;
    
    public async Task<bool> ConnectToEntraIDAsync()
    {
        try
        {
            using (var ps = PowerShell.Create())
            {
                // Load the authentication helper
                ps.AddScript(@"
                    . '.\indicators\IronVeil-ConnectEntraID.ps1'
                    Connect-IronVeilEntraID
                ");
                
                // This will open browser for interactive auth
                var results = await Task.Run(() => ps.Invoke());
                
                // Check if connection was successful
                ps.Commands.Clear();
                ps.AddScript("Test-IronVeilEntraIDConnection");
                var testResults = ps.Invoke();
                
                _isConnected = testResults.Any() && 
                              (bool)testResults[0].BaseObject == true;
                
                return _isConnected;
            }
        }
        catch (Exception ex)
        {
            // Log error
            return false;
        }
    }
    
    public bool IsConnected => _isConnected;
}
```

#### 3. Modify Rule Execution to Handle Authentication State

```csharp
// In PowerShellExecutor.cs
public async Task<List<RuleResult>> ExecuteRulesAsync(
    IProgress<RuleProgress> progress)
{
    var rules = DiscoverRules();
    var results = new List<RuleResult>();
    
    // Separate AD and Entra ID rules
    var adRules = rules.Where(r => r.Name.StartsWith("AD-"));
    var eidRules = rules.Where(r => r.Name.StartsWith("EID-"));
    
    // Execute AD rules (no auth needed - uses Windows auth)
    foreach (var rule in adRules)
    {
        var result = await ExecuteRuleAsync(rule);
        results.Add(result);
    }
    
    // Only execute EID rules if authenticated
    if (_entraIDAuth.IsConnected)
    {
        // Use the same PowerShell runspace to maintain auth
        using (var runspace = RunspaceFactory.CreateRunspace())
        {
            runspace.Open();
            
            // Ensure authentication context is available
            using (var ps = PowerShell.Create())
            {
                ps.Runspace = runspace;
                ps.AddScript(". '.\indicators\IronVeil-ConnectEntraID.ps1'");
                ps.Invoke();
                
                // Execute each EID rule in authenticated context
                foreach (var rule in eidRules)
                {
                    ps.Commands.Clear();
                    ps.AddScript(File.ReadAllText(rule.Path));
                    var ruleResults = ps.Invoke();
                    
                    if (ps.Streams.Error.Count > 0)
                    {
                        // Handle errors
                    }
                    else
                    {
                        // Process JSON results
                        results.Add(ParseResults(ruleResults));
                    }
                }
            }
        }
    }
    
    return results;
}
```

## Two Authentication Approaches

### Option 1: Interactive Authentication (Recommended for Desktop App)

**How it works:**
1. Desktop app loads `IronVeil-ConnectEntraID.ps1`
2. Calls `Connect-IronVeilEntraID` function
3. Browser opens for user authentication
4. User signs in with admin credentials
5. Token stored in PowerShell session
6. All EID rules execute using this authenticated session

**Pros:**
- Simple implementation
- Familiar to IT administrators
- No secret management
- User-delegated permissions

**Cons:**
- Requires user interaction each session
- Cannot be automated

**Implementation Code:**
```csharp
private async void ConnectEntraID_Click(object sender, RoutedEventArgs e)
{
    EntraIDStatusText.Text = "Connecting...";
    ConnectEntraIDButton.IsEnabled = false;
    
    var authManager = new EntraIDAuthenticationManager();
    bool connected = await authManager.ConnectToEntraIDAsync();
    
    if (connected)
    {
        EntraIDStatusText.Text = "Connected to Entra ID";
        EntraIDStatusText.Foreground = Brushes.Green;
        IncludeEntraIDRules.IsEnabled = true;
        IncludeEntraIDRules.IsChecked = true;
    }
    else
    {
        EntraIDStatusText.Text = "Connection failed";
        EntraIDStatusText.Foreground = Brushes.Red;
        IncludeEntraIDRules.IsEnabled = false;
    }
    
    ConnectEntraIDButton.IsEnabled = true;
}
```

### Option 2: Service Principal Authentication (For Future Automation)

**How it works:**
1. One-time setup creates app registration in Entra ID
2. Client secret stored securely (Windows Credential Manager)
3. Desktop app authenticates programmatically
4. No user interaction required

**Implementation would require:**
- Setup wizard for app registration
- Secure credential storage
- Token management and refresh logic
- More complex error handling

**Note:** This approach is **NOT currently implemented** but could be added for enterprise scenarios requiring automation.

## Step-by-Step Integration Guide

### For Desktop Application Developer

1. **Add UI Controls** for Entra ID authentication
   - Connection button
   - Status indicator
   - Option to include/exclude EID rules

2. **Implement Authentication Manager**
   ```csharp
   public class EntraIDAuthenticationManager
   {
       // See implementation above
   }
   ```

3. **Modify Rule Discovery**
   ```csharp
   private List<SecurityRule> DiscoverRules()
   {
       var rules = new List<SecurityRule>();
       var indicatorsPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "indicators");
       
       // Discover all rules
       var allRules = Directory.GetFiles(indicatorsPath, "*.ps1");
       
       foreach (var rulePath in allRules)
       {
           // Parse metadata
           var rule = ParseRuleMetadata(rulePath);
           
           // Mark EID rules as requiring authentication
           if (Path.GetFileName(rulePath).StartsWith("EID-"))
           {
               rule.RequiresEntraIDAuth = true;
           }
           
           rules.Add(rule);
       }
       
       return rules;
   }
   ```

4. **Handle Authentication State**
   - Check connection before executing EID rules
   - Skip EID rules if not authenticated
   - Provide clear user feedback

5. **Maintain PowerShell Session**
   - Keep runspace alive during scan
   - Reuse authenticated session for all EID rules
   - Dispose properly after completion

### For End Users

1. **First Time Setup**
   ```powershell
   # Install Microsoft.Graph module (one-time, ~150MB)
   Install-Module Microsoft.Graph -Scope CurrentUser
   ```

2. **Running a Scan**
   - Launch IronVeil Desktop Application
   - Click "Connect to Entra ID" button
   - Sign in when browser opens
   - Select "Run Scan" to include both AD and Entra ID checks

3. **Permissions Required**
   The following permissions will be requested during authentication:
   - Directory.Read.All
   - User.Read.All
   - Application.Read.All
   - Policy.Read.All
   - AuditLog.Read.All
   - Reports.Read.All
   - RoleManagement.Read.All
   - RoleManagement.Read.Directory
   - UserAuthenticationMethod.Read.All
   - AdministrativeUnit.Read.All
   - SecurityEvents.Read.All
   - Group.Read.All

## Testing the Integration

### 1. Test Authentication Flow
```csharp
[Test]
public async Task TestEntraIDAuthentication()
{
    var authManager = new EntraIDAuthenticationManager();
    
    // This will require manual interaction in test
    bool connected = await authManager.ConnectToEntraIDAsync();
    
    Assert.IsTrue(connected, "Failed to connect to Entra ID");
}
```

### 2. Test Rule Execution with Authentication
```csharp
[Test]
public async Task TestEIDRuleExecution()
{
    // First authenticate
    var authManager = new EntraIDAuthenticationManager();
    await authManager.ConnectToEntraIDAsync();
    
    // Then execute a test rule
    var executor = new PowerShellExecutor();
    var result = await executor.ExecuteRuleAsync("EID-T1-001.ps1");
    
    Assert.IsNotNull(result);
    Assert.AreEqual("Success", result.Status);
}
```

### 3. Test Graceful Degradation
```csharp
[Test]
public async Task TestScanWithoutEntraIDAuth()
{
    var executor = new PowerShellExecutor();
    var results = await executor.ExecuteAllRulesAsync();
    
    // Should still get AD results even without Entra ID auth
    var adResults = results.Where(r => r.RuleId.StartsWith("AD-"));
    Assert.IsTrue(adResults.Any(), "Should have AD results");
    
    // EID results should be skipped
    var eidResults = results.Where(r => r.RuleId.StartsWith("EID-"));
    Assert.IsFalse(eidResults.Any(), "Should not have EID results without auth");
}
```

## Common Issues and Solutions

### Issue 1: Browser doesn't open for authentication
**Solution:** Ensure default browser is configured and firewall allows outbound HTTPS

### Issue 2: "Module not found" error
**Solution:** Install Microsoft.Graph module:
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

### Issue 3: Permission denied during rule execution
**Solution:** Ensure admin consent was granted during authentication

### Issue 4: Token expires during long scan
**Solution:** Implement token refresh or re-authenticate mid-scan

## Security Considerations

1. **Token Storage**
   - Tokens are stored in PowerShell session memory only
   - Not persisted to disk
   - Cleared when application closes

2. **Permission Scope**
   - Only read-only permissions requested
   - Minimal scope for security assessment
   - No write permissions to Entra ID

3. **Audit Trail**
   - All authentication events logged in Entra ID
   - Sign-in logs show IronVeil access
   - Compliance-friendly approach

## Recommendations

### For Current Implementation (Phase 5)
1. **Implement Option 1** (Interactive Authentication)
   - Simpler to implement
   - Matches current use case (one-time scans)
   - Aligns with Microsoft.Graph module approach

2. **Add Clear UI Feedback**
   - Connection status indicator
   - Which rules will be executed
   - Progress during authentication

3. **Handle Edge Cases**
   - Module not installed
   - Authentication cancelled
   - Token expiration during scan

### For Future Enhancement (Phase 6+)
1. **Consider Service Principal** for enterprise customers
2. **Add token caching** between scans
3. **Implement parallel rule execution** for performance

## Conclusion

The Entra ID authentication framework is **ready for integration** into the desktop application. The PowerShell components are fully implemented and tested. The desktop application needs approximately **4-6 hours of development** to:

1. Add UI elements for authentication
2. Implement authentication manager
3. Modify rule executor for authenticated context
4. Test the complete flow

This integration will enable IronVeil to perform comprehensive security assessments across both on-premises Active Directory and cloud-based Entra ID environments, making it a complete hybrid identity security platform.

## Next Steps

1. **Desktop Developer** should implement the authentication manager class
2. **Add UI controls** for Entra ID connection in MainWindow
3. **Test the integration** with sample EID rules
4. **Update user documentation** with authentication instructions
5. **Consider adding** connection persistence options for better UX

---

**Status Summary:**
- ✅ PowerShell rules ready
- ✅ Authentication helper implemented  
- 🟡 Desktop integration needed (4-6 hours)
- ⏳ Testing and documentation to follow