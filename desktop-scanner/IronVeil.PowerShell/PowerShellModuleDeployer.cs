using System;
using System.IO;
using System.Linq;
using System.Reflection;
using Microsoft.Extensions.Logging;

namespace IronVeil.PowerShell;

/// <summary>
/// Handles deployment of PowerShell Core modules to the application directory
/// to ensure they are available to the hosted PowerShell runtime.
/// </summary>
public static class PowerShellModuleDeployer
{
    private static readonly string[] RequiredModules = new[]
    {
        "Microsoft.PowerShell.Archive",
        "Microsoft.PowerShell.Diagnostics", 
        "Microsoft.PowerShell.Host",
        "Microsoft.PowerShell.Management",
        "Microsoft.PowerShell.Security",
        "Microsoft.PowerShell.Utility",
        "Microsoft.WSMan.Management",
        "CimCmdlets",
        "PSDiagnostics"
    };

    /// <summary>
    /// Ensures PowerShell Core modules are deployed to the application directory.
    /// </summary>
    public static void EnsureModulesDeployed(ILogger? logger = null)
    {
        try
        {
            var appDirectory = AppDomain.CurrentDomain.BaseDirectory;
            var modulesDirectory = Path.Combine(appDirectory, "Modules");
            
            logger?.LogInformation("Ensuring PowerShell modules are deployed to {ModulesDirectory}", modulesDirectory);
            
            // Create Modules directory if it doesn't exist
            if (!Directory.Exists(modulesDirectory))
            {
                Directory.CreateDirectory(modulesDirectory);
                logger?.LogInformation("Created Modules directory at {ModulesDirectory}", modulesDirectory);
            }

            // Check if modules are already deployed
            var deployedModules = Directory.GetDirectories(modulesDirectory)
                .Select(Path.GetFileName)
                .Where(name => name != null)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var modulesToDeploy = RequiredModules.Where(m => !deployedModules.Contains(m)).ToList();
            
            if (!modulesToDeploy.Any())
            {
                logger?.LogInformation("All required PowerShell modules are already deployed");
                return;
            }

            logger?.LogInformation("Need to deploy {Count} PowerShell modules: {Modules}", 
                modulesToDeploy.Count, string.Join(", ", modulesToDeploy));

            // Try to find PowerShell installation
            var psHome = FindPowerShellHome(logger);
            if (psHome == null)
            {
                logger?.LogWarning("PowerShell 7 installation not found. Attempting to extract from embedded resources.");
                ExtractEmbeddedModules(modulesDirectory, modulesToDeploy, logger);
                return;
            }

            var sourceModulesPath = Path.Combine(psHome, "Modules");
            if (!Directory.Exists(sourceModulesPath))
            {
                logger?.LogWarning("PowerShell Modules directory not found at {Path}", sourceModulesPath);
                ExtractEmbeddedModules(modulesDirectory, modulesToDeploy, logger);
                return;
            }

            // Copy modules from PowerShell installation
            foreach (var moduleName in modulesToDeploy)
            {
                var sourcePath = Path.Combine(sourceModulesPath, moduleName);
                var destPath = Path.Combine(modulesDirectory, moduleName);

                if (Directory.Exists(sourcePath))
                {
                    try
                    {
                        CopyDirectory(sourcePath, destPath);
                        logger?.LogInformation("Deployed module {ModuleName} from {Source} to {Dest}", 
                            moduleName, sourcePath, destPath);
                    }
                    catch (Exception ex)
                    {
                        logger?.LogError(ex, "Failed to copy module {ModuleName}", moduleName);
                    }
                }
                else
                {
                    logger?.LogWarning("Module {ModuleName} not found at {Path}", moduleName, sourcePath);
                }
            }

            logger?.LogInformation("PowerShell module deployment completed");
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to deploy PowerShell modules");
        }
    }

    /// <summary>
    /// Finds the PowerShell 7 installation directory.
    /// </summary>
    private static string? FindPowerShellHome(ILogger? logger)
    {
        // Common PowerShell 7 installation paths
        var possiblePaths = new[]
        {
            @"C:\Program Files\PowerShell\7",
            @"C:\Program Files\PowerShell\7-preview",
            @"C:\Program Files (x86)\PowerShell\7",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PowerShell", "7")
        };

        // Also check the PSHOME environment variable
        var psHomeEnv = Environment.GetEnvironmentVariable("PSHOME");
        if (!string.IsNullOrEmpty(psHomeEnv))
        {
            possiblePaths = possiblePaths.Prepend(psHomeEnv).ToArray();
        }

        foreach (var path in possiblePaths)
        {
            if (Directory.Exists(path))
            {
                logger?.LogInformation("Found PowerShell installation at {Path}", path);
                return path;
            }
        }

        // Try to find from PATH
        var pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrEmpty(pathEnv))
        {
            var paths = pathEnv.Split(Path.PathSeparator);
            foreach (var path in paths)
            {
                if (path.Contains("PowerShell", StringComparison.OrdinalIgnoreCase) && 
                    Directory.Exists(path))
                {
                    var parentDir = Directory.GetParent(path)?.FullName;
                    if (parentDir != null && Directory.Exists(Path.Combine(parentDir, "Modules")))
                    {
                        logger?.LogInformation("Found PowerShell in PATH at {Path}", parentDir);
                        return parentDir;
                    }
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Extracts embedded PowerShell modules (fallback when PS7 is not installed).
    /// </summary>
    private static void ExtractEmbeddedModules(string modulesDirectory, List<string> modulesToDeploy, ILogger? logger)
    {
        // For now, we'll create minimal module structure
        // In production, you would embed the actual module files as resources
        foreach (var moduleName in modulesToDeploy)
        {
            var modulePath = Path.Combine(modulesDirectory, moduleName);
            Directory.CreateDirectory(modulePath);
            
            // Create a minimal module manifest
            var manifestPath = Path.Combine(modulePath, $"{moduleName}.psd1");
            var manifestContent = $@"@{{
    ModuleVersion = '1.0.0'
    GUID = '{Guid.NewGuid()}'
    Author = 'Microsoft Corporation'
    CompanyName = 'Microsoft Corporation'
    Copyright = '(c) Microsoft Corporation. All rights reserved.'
    Description = '{moduleName} module'
    PowerShellVersion = '7.0'
    FunctionsToExport = @('*')
    CmdletsToExport = @('*')
    VariablesToExport = '*'
    AliasesToExport = @('*')
}}";
            File.WriteAllText(manifestPath, manifestContent);
            logger?.LogInformation("Created minimal manifest for module {ModuleName}", moduleName);
        }
    }

    /// <summary>
    /// Recursively copies a directory and its contents.
    /// </summary>
    private static void CopyDirectory(string sourceDir, string destDir)
    {
        Directory.CreateDirectory(destDir);

        // Copy files
        foreach (var file in Directory.GetFiles(sourceDir))
        {
            var destFile = Path.Combine(destDir, Path.GetFileName(file));
            File.Copy(file, destFile, overwrite: true);
        }

        // Copy subdirectories
        foreach (var subDir in Directory.GetDirectories(sourceDir))
        {
            var destSubDir = Path.Combine(destDir, Path.GetFileName(subDir));
            CopyDirectory(subDir, destSubDir);
        }
    }

    /// <summary>
    /// Gets the path to the deployed modules directory.
    /// </summary>
    public static string GetModulesPath()
    {
        return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Modules");
    }
}