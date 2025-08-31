using System.Text.Json;

namespace IronVeil.Core.Configuration;

public class AppConfiguration
{
    private static AppConfiguration? _instance;
    private static readonly object _lock = new();
    
    public BackendSettings Backend { get; set; } = new();
    public ScanSettings Scan { get; set; } = new();
    public SecuritySettings Security { get; set; } = new();
    public ApplicationSettings Application { get; set; } = new();
    
    public static AppConfiguration Instance
    {
        get
        {
            if (_instance == null)
            {
                lock (_lock)
                {
                    _instance ??= Load();
                }
            }
            return _instance;
        }
    }
    
    private static string ConfigPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "IronVeil",
        "config.json"
    );
    
    public static AppConfiguration Load()
    {
        try
        {
            if (File.Exists(ConfigPath))
            {
                var json = File.ReadAllText(ConfigPath);
                return JsonSerializer.Deserialize<AppConfiguration>(json) ?? new AppConfiguration();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to load configuration: {ex.Message}");
        }
        
        return new AppConfiguration();
    }
    
    public void Save()
    {
        try
        {
            var directory = Path.GetDirectoryName(ConfigPath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }
            
            var options = new JsonSerializerOptions
            {
                WriteIndented = true
            };
            
            var json = JsonSerializer.Serialize(this, options);
            File.WriteAllText(ConfigPath, json);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to save configuration: {ex.Message}");
        }
    }
}

public class BackendSettings
{
    public string DefaultBackend { get; set; } = "https://ironveil.crimson7.io";
    public List<string> CustomBackends { get; set; } = new();
    public string? LastUsedBackend { get; set; }
    public bool RememberSelection { get; set; } = true;
}

public class ScanSettings
{
    public bool ScanActiveDirectory { get; set; } = true;
    public bool ScanEntraId { get; set; } = true;
    public bool ScanHybridIdentity { get; set; } = true;
    public ScanDepth DefaultDepth { get; set; } = ScanDepth.Standard;
    public int MaxParallelRules { get; set; } = 5;
    public int RuleTimeoutSeconds { get; set; } = 30;
    public List<string> ExcludedRules { get; set; } = new();
}

public class SecuritySettings
{
    public bool StoreCredentials { get; set; } = false;
    public bool EncryptLocalResults { get; set; } = true;
    public bool AutoUploadResults { get; set; } = true;
    public int SessionTimeoutMinutes { get; set; } = 60;
}

public class ApplicationSettings
{
    public string Version { get; set; } = "1.0.0";
    public bool CheckForUpdates { get; set; } = true;
    public bool EnableTelemetry { get; set; } = false;
    public string LogLevel { get; set; } = "Information";
    public bool MinimizeToTray { get; set; } = false;
    public string Theme { get; set; } = "Light";
}

public enum ScanDepth
{
    Quick,
    Standard,
    Deep
}