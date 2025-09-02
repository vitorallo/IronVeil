using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace PowerShellTest;

public class TestRunner
{
    public async Task TestInitializationMethod(string methodName, Func<InitialSessionState> createSessionState)
    {
        Console.WriteLine($"================================================================================");
        Console.WriteLine($"TEST: {methodName}");
        Console.WriteLine($"================================================================================");
        
        try
        {
            // Create session state
            var sessionState = createSessionState();
            Console.WriteLine($"✅ Session state created successfully");
            Console.WriteLine($"   Language Mode: {sessionState.LanguageMode}");
            Console.WriteLine($"   Execution Policy: {sessionState.ExecutionPolicy}");
            
            // Create runspace
            using var runspace = RunspaceFactory.CreateRunspace(sessionState);
            runspace.Open();
            Console.WriteLine($"✅ Runspace opened successfully");
            
            // Test basic PowerShell commands
            using var powerShell = PowerShell.Create();
            powerShell.Runspace = runspace;
            
            // Test 1: Get-Date
            await TestCommand(powerShell, "Get-Date");
            
            // Test 2: Get-Date with format
            await TestCommand(powerShell, "Get-Date -Format 'o'");
            
            // Test 3: Get-Command Get-Date
            await TestCommand(powerShell, "Get-Command Get-Date");
            
            // Test 4: Check available modules
            await TestCommand(powerShell, "Get-Module -ListAvailable | Select-Object -First 5 Name");
            
            // Test 5: Check PowerShell paths
            await TestCommand(powerShell, "$PSHOME");
            await TestCommand(powerShell, "$env:PSModulePath");
            
            // Test 6: PowerShell version
            await TestCommand(powerShell, "$PSVersionTable.PSVersion");
            
            Console.WriteLine($"✅ All tests completed for {methodName}");
            
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ FAILED: {methodName}");
            Console.WriteLine($"   Error: {ex.GetType().Name}: {ex.Message}");
            if (ex.InnerException != null)
            {
                Console.WriteLine($"   Inner: {ex.InnerException.GetType().Name}: {ex.InnerException.Message}");
            }
        }
        
        Console.WriteLine();
    }
    
    private async Task TestCommand(PowerShell powerShell, string command)
    {
        try
        {
            Console.Write($"   Testing: {command}... ");
            
            powerShell.Commands.Clear();
            powerShell.AddScript(command);
            
            var results = await Task.Run(() => powerShell.Invoke());
            
            if (powerShell.HadErrors)
            {
                Console.WriteLine("❌ ERROR");
                foreach (var error in powerShell.Streams.Error)
                {
                    Console.WriteLine($"     {error.Exception?.GetType().Name}: {error.Exception?.Message}");
                }
                powerShell.Streams.Error.Clear();
            }
            else
            {
                Console.WriteLine("✅ SUCCESS");
                if (results.Any())
                {
                    var result = results.First()?.ToString();
                    if (!string.IsNullOrEmpty(result) && result.Length < 100)
                    {
                        Console.WriteLine($"     Result: {result}");
                    }
                    else if (!string.IsNullOrEmpty(result))
                    {
                        Console.WriteLine($"     Result: {result.Substring(0, 97)}...");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ EXCEPTION: {ex.GetType().Name}: {ex.Message}");
        }
    }
    
    public async Task TestEnvironmentVariables()
    {
        Console.WriteLine($"================================================================================");
        Console.WriteLine($"ENVIRONMENT VARIABLE TESTS");
        Console.WriteLine($"================================================================================");
        
        // Display current environment
        Console.WriteLine("Current Environment Variables:");
        Console.WriteLine($"   PSHOME: {Environment.GetEnvironmentVariable("PSHOME") ?? "Not set"}");
        Console.WriteLine($"   PSModulePath: {Environment.GetEnvironmentVariable("PSModulePath") ?? "Not set"}");
        Console.WriteLine($"   DOTNET_ROOT: {Environment.GetEnvironmentVariable("DOTNET_ROOT") ?? "Not set"}");
        Console.WriteLine();
        
        // Try setting PSHOME and test
        try 
        {
            // Find PowerShell installation
            var possiblePSHomes = new[]
            {
                @"C:\Program Files\PowerShell\7",
                @"C:\Program Files (x86)\PowerShell\7",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PowerShell", "7"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "powershell")
            };
            
            string? foundPSHome = null;
            foreach (var path in possiblePSHomes)
            {
                if (Directory.Exists(path))
                {
                    var psExePath = Path.Combine(path, "pwsh.exe");
                    if (File.Exists(psExePath))
                    {
                        foundPSHome = path;
                        break;
                    }
                }
            }
            
            if (foundPSHome != null)
            {
                Console.WriteLine($"Found PowerShell installation: {foundPSHome}");
                
                // Set PSHOME temporarily
                Environment.SetEnvironmentVariable("PSHOME", foundPSHome);
                
                // Set module path
                var modulePath = Path.Combine(foundPSHome, "Modules");
                if (Directory.Exists(modulePath))
                {
                    Environment.SetEnvironmentVariable("PSModulePath", modulePath);
                    Console.WriteLine($"Set PSModulePath to: {modulePath}");
                }
                
                // Test with updated environment
                await TestInitializationMethod("CreateDefault2 + PSHOME", () => InitialSessionState.CreateDefault2());
            }
            else
            {
                Console.WriteLine("❌ Could not locate PowerShell installation");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Environment test failed: {ex.Message}");
        }
        
        Console.WriteLine();
    }
    
    public async Task TestExplicitPSHomeFix()
    {
        Console.WriteLine($"================================================================================");
        Console.WriteLine($"EXPLICIT PSHOME FIX TEST");
        Console.WriteLine($"================================================================================");
        
        try
        {
            // Find and set correct PSHOME BEFORE creating session state
            var correctPSHome = @"C:\Program Files\PowerShell\7";
            if (Directory.Exists(correctPSHome))
            {
                Console.WriteLine($"Setting PSHOME to: {correctPSHome}");
                
                // Create session state with explicit PSHOME
                var sessionState = InitialSessionState.CreateDefault2();
                
                // Manually override PSHOME variable in the session
                var psHomeVar = new SessionStateVariableEntry("PSHOME", correctPSHome, "PowerShell Home Directory");
                sessionState.Variables.Add(psHomeVar);
                
                // Add correct module path
                var modulePathVar = new SessionStateVariableEntry("PSModulePath", 
                    Path.Combine(correctPSHome, "Modules"), "PowerShell Module Path");
                sessionState.Variables.Add(modulePathVar);
                
                Console.WriteLine($"✅ Session state created with explicit PSHOME");
                
                using var runspace = RunspaceFactory.CreateRunspace(sessionState);
                runspace.Open();
                Console.WriteLine($"✅ Runspace opened successfully");
                
                using var powerShell = PowerShell.Create();
                powerShell.Runspace = runspace;
                
                // Test the fix
                await TestCommand(powerShell, "$PSHOME");
                await TestCommand(powerShell, "Get-Date");
                await TestCommand(powerShell, "Get-Date -Format 'o'");
                
                Console.WriteLine($"✅ PSHOME fix test completed");
            }
            else
            {
                Console.WriteLine($"❌ PowerShell installation not found at {correctPSHome}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ PSHOME fix test failed: {ex.GetType().Name}: {ex.Message}");
        }
        
        Console.WriteLine();
    }
}