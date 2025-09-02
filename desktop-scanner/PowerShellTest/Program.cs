using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace PowerShellTest;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("================================================================================");
        Console.WriteLine("POWERSHELL MODULE LOADING TEST UTILITY");
        Console.WriteLine("================================================================================");
        Console.WriteLine($"Environment: .NET {Environment.Version}");
        Console.WriteLine($"OS: {Environment.OSVersion}");
        Console.WriteLine($"Working Directory: {Environment.CurrentDirectory}");
        Console.WriteLine();

        var testRunner = new TestRunner();
        
        Console.WriteLine("Testing different PowerShell initialization methods...");
        Console.WriteLine();
        
        // Test 1: CreateDefault2()
        await testRunner.TestInitializationMethod("CreateDefault2", () => InitialSessionState.CreateDefault2());
        
        // Test 2: CreateDefault()
        await testRunner.TestInitializationMethod("CreateDefault", () => InitialSessionState.CreateDefault());
        
        // Test 3: Create() (empty)
        await testRunner.TestInitializationMethod("Create (Empty)", () => InitialSessionState.Create());
        
        // Test 4: Create() with manual module imports
        await testRunner.TestInitializationMethod("Create + Manual Imports", () => 
        {
            var iss = InitialSessionState.Create();
            try
            {
                iss.ImportPSModule(new[] { 
                    "Microsoft.PowerShell.Core",
                    "Microsoft.PowerShell.Utility", 
                    "Microsoft.PowerShell.Management"
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    Warning: Manual import failed: {ex.Message}");
            }
            return iss;
        });
        
        // Test 5: Environment variable tests
        await testRunner.TestEnvironmentVariables();
        
        // Test 6: Explicit PSHOME fix
        await testRunner.TestExplicitPSHomeFix();
        
        Console.WriteLine("\n================================================================================");
        Console.WriteLine("TEST SUMMARY COMPLETE");
        Console.WriteLine("================================================================================");
        
        Console.WriteLine("Test completed.");
    }
}