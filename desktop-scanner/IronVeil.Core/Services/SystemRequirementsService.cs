using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Management.Automation;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace IronVeil.Core.Services;

public interface ISystemRequirementsService
{
    Task<SystemRequirements> CheckRequirementsAsync();
    Task<List<string>> GetAvailableDomainsAsync();
    Task<string?> GetCurrentDomainAsync();
}

public class SystemRequirementsService : ISystemRequirementsService
{
    private readonly ILogger<SystemRequirementsService>? _logger;

    public SystemRequirementsService(ILogger<SystemRequirementsService>? logger = null)
    {
        _logger = logger;
    }

    public async Task<SystemRequirements> CheckRequirementsAsync()
    {
        var requirements = new SystemRequirements();
        
        await Task.Run(() =>
        {
            // Check PowerShell availability
            requirements.PowerShellAvailable = CheckPowerShellAvailable();
            requirements.PowerShellVersion = GetPowerShellVersion();
            
            // Check domain membership
            requirements.IsDomainJoined = CheckDomainMembership();
            requirements.CurrentDomain = GetCurrentDomainName();
            
            // Check for Active Directory module
            requirements.ActiveDirectoryModuleAvailable = CheckActiveDirectoryModule();
            
            // Check for administrative privileges
            requirements.IsAdministrator = CheckIsAdministrator();
            
            // Get available domains in forest
            if (requirements.IsDomainJoined)
            {
                requirements.AvailableDomains = GetDomainsInForest();
            }
        });
        
        _logger?.LogInformation("System requirements check completed: PowerShell={PS}, Domain={Domain}, AD Module={AD}, Admin={Admin}",
            requirements.PowerShellAvailable, requirements.IsDomainJoined, 
            requirements.ActiveDirectoryModuleAvailable, requirements.IsAdministrator);
        
        return requirements;
    }

    public async Task<List<string>> GetAvailableDomainsAsync()
    {
        return await Task.Run(() => GetDomainsInForest());
    }

    public async Task<string?> GetCurrentDomainAsync()
    {
        return await Task.Run(() => GetCurrentDomainName());
    }

    private bool CheckPowerShellAvailable()
    {
        try
        {
            using var ps = PowerShell.Create();
            ps.AddScript("$PSVersionTable.PSVersion");
            var results = ps.Invoke();
            return !ps.HadErrors && results.Count > 0;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to check PowerShell availability");
            return false;
        }
    }

    private string GetPowerShellVersion()
    {
        try
        {
            using var ps = PowerShell.Create();
            ps.AddScript("$PSVersionTable.PSVersion.ToString()");
            var results = ps.Invoke();
            if (!ps.HadErrors && results.Count > 0)
            {
                return results[0]?.ToString() ?? "Unknown";
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to get PowerShell version");
        }
        return "Not Available";
    }

    private bool CheckDomainMembership()
    {
        try
        {
            // Check if computer is domain joined
            string domainName = Environment.UserDomainName;
            string machineName = Environment.MachineName;
            
            // If domain name equals machine name, it's not domain joined
            if (string.Equals(domainName, machineName, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            
            // Try to get domain context
            try
            {
                using var context = new PrincipalContext(ContextType.Domain);
                return context.ConnectedServer != null;
            }
            catch
            {
                // Not in a domain or cannot connect
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to check domain membership");
            return false;
        }
    }

    private string? GetCurrentDomainName()
    {
        try
        {
            if (!CheckDomainMembership())
                return null;
            
            // Get domain from environment
            string domainName = Environment.UserDomainName;
            string machineName = Environment.MachineName;
            
            if (!string.Equals(domainName, machineName, StringComparison.OrdinalIgnoreCase))
            {
                return domainName;
            }
            
            // Try to get from PrincipalContext
            try
            {
                using var context = new PrincipalContext(ContextType.Domain);
                return context.Name ?? context.ConnectedServer;
            }
            catch
            {
                return domainName;
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to get current domain name");
            return null;
        }
    }

    private List<string> GetDomainsInForest()
    {
        var domains = new List<string>();
        
        try
        {
            // For now, just return the current domain
            // Full forest enumeration would require System.DirectoryServices.ActiveDirectory
            // which is not available in .NET Core/5+
            var currentDomain = GetCurrentDomainName();
            if (!string.IsNullOrEmpty(currentDomain))
            {
                domains.Add(currentDomain);
                
                // Try to discover other domains using LDAP
                try
                {
                    using var rootEntry = new DirectoryEntry($"LDAP://{currentDomain}");
                    using var searcher = new DirectorySearcher(rootEntry)
                    {
                        Filter = "(objectClass=trustedDomain)",
                        PropertiesToLoad = { "name", "trustPartner" }
                    };
                    
                    var results = searcher.FindAll();
                    foreach (SearchResult result in results)
                    {
                        if (result.Properties["trustPartner"].Count > 0)
                        {
                            var trustPartner = result.Properties["trustPartner"][0]?.ToString();
                            if (!string.IsNullOrEmpty(trustPartner) && !domains.Contains(trustPartner))
                            {
                                domains.Add(trustPartner);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Could not enumerate trusted domains");
                }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to enumerate domains in forest");
        }
        
        return domains;
    }

    private bool CheckActiveDirectoryModule()
    {
        try
        {
            using var ps = PowerShell.Create();
            ps.AddScript("Get-Module -ListAvailable -Name ActiveDirectory");
            var results = ps.Invoke();
            return !ps.HadErrors && results.Count > 0;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to check for Active Directory module");
            return false;
        }
    }

    private bool CheckIsAdministrator()
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            return false;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to check administrator status");
            return false;
        }
    }
}

public class SystemRequirements
{
    public bool PowerShellAvailable { get; set; }
    public string PowerShellVersion { get; set; } = "Not Available";
    public bool IsDomainJoined { get; set; }
    public string? CurrentDomain { get; set; }
    public List<string> AvailableDomains { get; set; } = new();
    public bool ActiveDirectoryModuleAvailable { get; set; }
    public bool IsAdministrator { get; set; }
    
    public bool CanRunActiveDirectoryScans => IsDomainJoined && PowerShellAvailable;
    public bool CanRunEntraIdScans => PowerShellAvailable; // Entra ID doesn't require domain join
    
    public List<string> GetIssues()
    {
        var issues = new List<string>();
        
        if (!PowerShellAvailable)
        {
            issues.Add("PowerShell is not available or not properly configured");
        }
        
        if (!IsDomainJoined)
        {
            issues.Add("Computer is not joined to an Active Directory domain");
        }
        
        if (!ActiveDirectoryModuleAvailable)
        {
            issues.Add("Active Directory PowerShell module is not installed");
        }
        
        if (!IsAdministrator)
        {
            issues.Add("Application is not running with administrator privileges (some checks may fail)");
        }
        
        return issues;
    }
    
    public string GetStatusSummary()
    {
        if (CanRunActiveDirectoryScans && CanRunEntraIdScans)
        {
            return $"Ready to scan {CurrentDomain ?? "local environment"}";
        }
        else if (CanRunEntraIdScans)
        {
            return "Ready for Entra ID scans only (not domain joined)";
        }
        else
        {
            return "Missing requirements - check status panel";
        }
    }
}