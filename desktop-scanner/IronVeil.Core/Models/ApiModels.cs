using System.Text.Json.Serialization;

namespace IronVeil.Core.Models;

public class ScanUploadRequest
{
    [JsonPropertyName("sessionId")]
    public string SessionId { get; set; } = string.Empty;
    
    [JsonPropertyName("results")]
    public List<ScanResult> Results { get; set; } = new();
    
    [JsonPropertyName("configuration")]
    public ScanConfiguration Configuration { get; set; } = new();
    
    [JsonPropertyName("metadata")]
    public UploadMetadata Metadata { get; set; } = new();
}

public class UploadMetadata
{
    [JsonPropertyName("scannerVersion")]
    public string ScannerVersion { get; set; } = "1.0.0";
    
    [JsonPropertyName("platform")]
    public string Platform { get; set; } = "Windows";
    
    [JsonPropertyName("totalRules")]
    public int TotalRules { get; set; }
    
    [JsonPropertyName("successfulRules")]
    public int SuccessfulRules { get; set; }
    
    [JsonPropertyName("failedRules")]
    public int FailedRules { get; set; }
    
    [JsonPropertyName("duration")]
    public double Duration { get; set; }
    
    [JsonPropertyName("environment")]
    public Dictionary<string, string> Environment { get; set; } = new();
}

public class ApiResponse<T>
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }
    
    [JsonPropertyName("data")]
    public T? Data { get; set; }
    
    [JsonPropertyName("error")]
    public string? Error { get; set; }
    
    [JsonPropertyName("message")]
    public string? Message { get; set; }
    
    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

public class ScanUploadResponse
{
    [JsonPropertyName("uploadId")]
    public string UploadId { get; set; } = string.Empty;
    
    [JsonPropertyName("processed")]
    public bool Processed { get; set; }
    
    [JsonPropertyName("dashboardUrl")]
    public string? DashboardUrl { get; set; }
    
    [JsonPropertyName("summary")]
    public ScanSummary Summary { get; set; } = new();
}

public class ScanSummary
{
    [JsonPropertyName("totalFindings")]
    public int TotalFindings { get; set; }
    
    [JsonPropertyName("criticalCount")]
    public int CriticalCount { get; set; }
    
    [JsonPropertyName("highCount")]
    public int HighCount { get; set; }
    
    [JsonPropertyName("mediumCount")]
    public int MediumCount { get; set; }
    
    [JsonPropertyName("lowCount")]
    public int LowCount { get; set; }
    
    [JsonPropertyName("overallScore")]
    public double OverallScore { get; set; }
}

public class BackendInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;
    
    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;
    
    [JsonPropertyName("features")]
    public List<string> Features { get; set; } = new();
    
    [JsonPropertyName("oauth")]
    public OAuthConfiguration OAuth { get; set; } = new();
    
    [JsonPropertyName("endpoints")]
    public Dictionary<string, string> Endpoints { get; set; } = new();
}