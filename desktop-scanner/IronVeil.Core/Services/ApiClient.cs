using IronVeil.Core.Models;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace IronVeil.Core.Services;

public interface IApiClient
{
    Task<ApiResponse<ScanUploadResponse>> UploadScanResultsAsync(ScanUploadRequest request, CancellationToken cancellationToken = default);
    Task<ApiResponse<BackendInfo>> GetBackendInfoAsync(string backendUrl, CancellationToken cancellationToken = default);
    Task<bool> TestConnectionAsync(string backendUrl, CancellationToken cancellationToken = default);
    string? CurrentBackendUrl { get; set; }
}

public class ApiClient : IApiClient
{
    private readonly HttpClient _httpClient;
    private readonly IAuthenticationService _authenticationService;
    private readonly ILogger<ApiClient>? _logger;
    private readonly Queue<ScanUploadRequest> _offlineQueue = new();
    private readonly SemaphoreSlim _uploadSemaphore = new(1, 1);
    
    public string? CurrentBackendUrl { get; set; }

    public ApiClient(HttpClient httpClient, IAuthenticationService authenticationService, ILogger<ApiClient>? logger = null)
    {
        _httpClient = httpClient;
        _authenticationService = authenticationService;
        _logger = logger;
        
        // Configure HttpClient
        _httpClient.Timeout = TimeSpan.FromMinutes(5);
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "IronVeil-Desktop/1.0.0");
    }

    public async Task<ApiResponse<ScanUploadResponse>> UploadScanResultsAsync(ScanUploadRequest request, CancellationToken cancellationToken = default)
    {
        await _uploadSemaphore.WaitAsync(cancellationToken);
        
        try
        {
            // Ensure we have authentication
            if (!_authenticationService.IsAuthenticated)
            {
                return new ApiResponse<ScanUploadResponse>
                {
                    Success = false,
                    Error = "Not authenticated",
                    Message = "Authentication required to upload scan results"
                };
            }

            // Prepare request with authentication
            using var httpRequest = new HttpRequestMessage(HttpMethod.Post, $"{CurrentBackendUrl?.TrimEnd('/')}/api/scans/upload");
            httpRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _authenticationService.CurrentAccessToken);
            
            var jsonContent = JsonSerializer.Serialize(request, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
            httpRequest.Content = new StringContent(jsonContent, System.Text.Encoding.UTF8, "application/json");

            _logger?.LogInformation("Uploading scan results for session {SessionId} with {ResultCount} results", 
                request.SessionId, request.Results.Count);

            // Send request with retry logic
            var response = await SendWithRetryAsync(httpRequest, cancellationToken);
            
            if (response.IsSuccessStatusCode)
            {
                var apiResponse = await response.Content.ReadFromJsonAsync<ApiResponse<ScanUploadResponse>>(cancellationToken: cancellationToken);
                if (apiResponse != null)
                {
                    _logger?.LogInformation("Successfully uploaded scan results. Upload ID: {UploadId}", apiResponse.Data?.UploadId);
                    
                    // Process offline queue if we're back online
                    _ = Task.Run(() => ProcessOfflineQueueAsync(CancellationToken.None));
                    
                    return apiResponse;
                }
            }

            // Handle authentication errors
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                _logger?.LogWarning("Authentication failed during upload, attempting token refresh");
                
                var refreshResult = await _authenticationService.RefreshTokenAsync(cancellationToken);
                if (refreshResult.IsSuccess)
                {
                    // Retry the request with new token
                    httpRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", refreshResult.AccessToken);
                    response = await SendWithRetryAsync(httpRequest, cancellationToken);
                    
                    if (response.IsSuccessStatusCode)
                    {
                        var apiResponse = await response.Content.ReadFromJsonAsync<ApiResponse<ScanUploadResponse>>(cancellationToken: cancellationToken);
                        if (apiResponse != null)
                        {
                            return apiResponse;
                        }
                    }
                }
            }

            // Handle offline scenario - queue for later upload
            if (!await TestConnectionAsync(CurrentBackendUrl!, cancellationToken))
            {
                _logger?.LogInformation("Backend offline, queuing scan results for later upload");
                QueueForOfflineUpload(request);
                
                return new ApiResponse<ScanUploadResponse>
                {
                    Success = true,
                    Message = "Scan results queued for upload when connection is restored",
                    Data = new ScanUploadResponse
                    {
                        UploadId = $"offline-{Guid.NewGuid()}",
                        Processed = false
                    }
                };
            }

            // Failed upload
            var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
            _logger?.LogError("Failed to upload scan results: {StatusCode} - {Error}", response.StatusCode, errorContent);
            
            return new ApiResponse<ScanUploadResponse>
            {
                Success = false,
                Error = $"Upload failed: {response.StatusCode}",
                Message = errorContent
            };
        }
        catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
        {
            _logger?.LogError("Upload timeout for session {SessionId}", request.SessionId);
            QueueForOfflineUpload(request);
            
            return new ApiResponse<ScanUploadResponse>
            {
                Success = false,
                Error = "Upload timeout",
                Message = "Request timed out, results queued for retry"
            };
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Unexpected error during scan upload for session {SessionId}", request.SessionId);
            QueueForOfflineUpload(request);
            
            return new ApiResponse<ScanUploadResponse>
            {
                Success = false,
                Error = "Upload failed",
                Message = ex.Message
            };
        }
        finally
        {
            _uploadSemaphore.Release();
        }
    }

    public async Task<ApiResponse<BackendInfo>> GetBackendInfoAsync(string backendUrl, CancellationToken cancellationToken = default)
    {
        try
        {
            var infoUrl = $"{backendUrl.TrimEnd('/')}/api/info";
            var response = await _httpClient.GetAsync(infoUrl, cancellationToken);
            
            if (response.IsSuccessStatusCode)
            {
                var backendInfo = await response.Content.ReadFromJsonAsync<BackendInfo>(cancellationToken: cancellationToken);
                
                return new ApiResponse<BackendInfo>
                {
                    Success = true,
                    Data = backendInfo,
                    Message = "Backend info retrieved successfully"
                };
            }

            return new ApiResponse<BackendInfo>
            {
                Success = false,
                Error = "Failed to retrieve backend info",
                Message = $"HTTP {response.StatusCode}"
            };
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to get backend info from {BackendUrl}", backendUrl);
            
            return new ApiResponse<BackendInfo>
            {
                Success = false,
                Error = "Connection failed",
                Message = ex.Message
            };
        }
    }

    public async Task<bool> TestConnectionAsync(string backendUrl, CancellationToken cancellationToken = default)
    {
        try
        {
            var healthUrl = $"{backendUrl.TrimEnd('/')}/api/health";
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(10)); // 10-second timeout for connection test
            
            var response = await _httpClient.GetAsync(healthUrl, cts.Token);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Connection test failed for {BackendUrl}", backendUrl);
            return false;
        }
    }

    private async Task<HttpResponseMessage> SendWithRetryAsync(HttpRequestMessage request, CancellationToken cancellationToken, int maxRetries = 3)
    {
        Exception? lastException = null;
        
        for (int attempt = 1; attempt <= maxRetries; attempt++)
        {
            try
            {
                // Clone the request for retry attempts
                var clonedRequest = await CloneHttpRequestAsync(request);
                var response = await _httpClient.SendAsync(clonedRequest, cancellationToken);
                
                // Don't retry on client errors (4xx), only server errors (5xx) and network issues
                if (response.IsSuccessStatusCode || ((int)response.StatusCode >= 400 && (int)response.StatusCode < 500))
                {
                    return response;
                }
                
                _logger?.LogWarning("HTTP request failed on attempt {Attempt}/{MaxRetries}: {StatusCode}", 
                    attempt, maxRetries, response.StatusCode);
                
                if (attempt < maxRetries)
                {
                    var delay = TimeSpan.FromSeconds(Math.Pow(2, attempt)); // Exponential backoff
                    await Task.Delay(delay, cancellationToken);
                }
                else
                {
                    return response; // Return the last response even if failed
                }
            }
            catch (Exception ex) when (!(ex is OperationCanceledException))
            {
                lastException = ex;
                _logger?.LogWarning(ex, "HTTP request exception on attempt {Attempt}/{MaxRetries}", attempt, maxRetries);
                
                if (attempt < maxRetries)
                {
                    var delay = TimeSpan.FromSeconds(Math.Pow(2, attempt));
                    await Task.Delay(delay, cancellationToken);
                }
            }
        }
        
        throw lastException ?? new HttpRequestException($"Request failed after {maxRetries} attempts");
    }

    private async Task<HttpRequestMessage> CloneHttpRequestAsync(HttpRequestMessage original)
    {
        var clone = new HttpRequestMessage(original.Method, original.RequestUri);
        
        // Copy headers
        foreach (var header in original.Headers)
        {
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        
        // Copy content
        if (original.Content != null)
        {
            var contentBytes = await original.Content.ReadAsByteArrayAsync();
            clone.Content = new ByteArrayContent(contentBytes);
            
            // Copy content headers
            foreach (var header in original.Content.Headers)
            {
                clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }
        
        return clone;
    }

    private void QueueForOfflineUpload(ScanUploadRequest request)
    {
        try
        {
            _offlineQueue.Enqueue(request);
            _logger?.LogInformation("Queued scan results for offline upload. Queue size: {QueueSize}", _offlineQueue.Count);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to queue scan results for offline upload");
        }
    }

    private async Task ProcessOfflineQueueAsync(CancellationToken cancellationToken)
    {
        if (_offlineQueue.Count == 0) return;
        
        _logger?.LogInformation("Processing offline upload queue with {QueueSize} items", _offlineQueue.Count);
        
        while (_offlineQueue.Count > 0 && !cancellationToken.IsCancellationRequested)
        {
            try
            {
                // Test connection first
                if (!await TestConnectionAsync(CurrentBackendUrl!, cancellationToken))
                {
                    _logger?.LogDebug("Backend still offline, stopping queue processing");
                    break;
                }

                var request = _offlineQueue.Dequeue();
                var result = await UploadScanResultsAsync(request, cancellationToken);
                
                if (!result.Success)
                {
                    // Re-queue on failure
                    _offlineQueue.Enqueue(request);
                    _logger?.LogWarning("Failed to upload queued scan results, re-queuing");
                    break;
                }
                
                _logger?.LogInformation("Successfully uploaded queued scan results");
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error processing offline upload queue");
                break;
            }
        }
    }
}