using System.Text.Json.Serialization;

namespace IronVeil.Core.Models;

public class ScanResult
{
    [JsonPropertyName("checkId")]
    public string CheckId { get; set; } = string.Empty;
    
    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; } = DateTime.UtcNow.ToString("o");
    
    [JsonPropertyName("status")]
    public string Status { get; set; } = "Success";
    
    [JsonPropertyName("score")]
    public int Score { get; set; }
    
    [JsonPropertyName("severity")]
    public string Severity { get; set; } = "Low";
    
    [JsonPropertyName("category")]
    public string Category { get; set; } = string.Empty;
    
    [JsonPropertyName("findings")]
    public List<Finding> Findings { get; set; } = new();
    
    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;
    
    [JsonPropertyName("affectedObjects")]
    public int AffectedObjects { get; set; }
    
    [JsonPropertyName("ignoredObjects")]
    public int IgnoredObjects { get; set; }
    
    [JsonPropertyName("metadata")]
    public ScanMetadata Metadata { get; set; } = new();
}

public class Finding
{
    [JsonPropertyName("objectName")]
    public string ObjectName { get; set; } = string.Empty;
    
    [JsonPropertyName("objectType")]
    public string ObjectType { get; set; } = string.Empty;
    
    [JsonPropertyName("riskLevel")]
    public string RiskLevel { get; set; } = "Low";
    
    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;
    
    [JsonPropertyName("remediation")]
    public string Remediation { get; set; } = string.Empty;
    
    [JsonPropertyName("affectedAttributes")]
    public List<string> AffectedAttributes { get; set; } = new();
}

public class ScanMetadata
{
    [JsonPropertyName("domain")]
    public string? Domain { get; set; }
    
    [JsonPropertyName("tenantId")]
    public string? TenantId { get; set; }
    
    [JsonPropertyName("executionTime")]
    public double ExecutionTime { get; set; }
    
    [JsonPropertyName("ruleVersion")]
    public string? RuleVersion { get; set; }
    
    [JsonPropertyName("environment")]
    public string? Environment { get; set; }
}

public class ScanSession
{
    public string SessionId { get; set; } = Guid.NewGuid().ToString();
    public DateTime StartTime { get; set; } = DateTime.UtcNow;
    public DateTime? EndTime { get; set; }
    public ScanConfiguration Configuration { get; set; } = new();
    public List<ScanResult> Results { get; set; } = new();
    public ScanStatus Status { get; set; } = ScanStatus.NotStarted;
    public string? ErrorMessage { get; set; }
}

public class ScanConfiguration
{
    public bool ScanActiveDirectory { get; set; } = true;
    public bool ScanEntraId { get; set; } = true;
    public bool ScanHybridIdentity { get; set; } = true;
    public List<string> IncludedRules { get; set; } = new();
    public List<string> ExcludedRules { get; set; } = new();
    public int MaxParallelRules { get; set; } = 5;
    public int RuleTimeoutSeconds { get; set; } = 30;
}

public enum ScanStatus
{
    NotStarted,
    Running,
    Completed,
    Failed,
    Cancelled
}

public enum SeverityLevel
{
    Low = 25,
    Medium = 50,
    High = 75,
    Critical = 100
}