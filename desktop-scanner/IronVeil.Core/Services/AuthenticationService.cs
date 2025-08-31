using IronVeil.Core.Models;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;

namespace IronVeil.Core.Services;

public interface IAuthenticationService
{
    event EventHandler<AuthenticationResult>? AuthenticationCompleted;
    Task<AuthenticationResult> AuthenticateAsync(string backendUrl, CancellationToken cancellationToken = default);
    Task<AuthenticationResult> RefreshTokenAsync(CancellationToken cancellationToken = default);
    Task LogoutAsync();
    bool IsAuthenticated { get; }
    string? CurrentUsername { get; }
    string? CurrentAccessToken { get; }
    DateTime? TokenExpiresAt { get; }
}

public class AuthenticationService : IAuthenticationService, IDisposable
{
    private readonly IConfigurationService _configurationService;
    private readonly HttpClient _httpClient;
    private readonly ILogger<AuthenticationService>? _logger;
    
    private AuthenticationResult? _currentAuth;
    private OAuthConfiguration? _oauthConfig;
    private HttpListener? _callbackListener;
    
    public event EventHandler<AuthenticationResult>? AuthenticationCompleted;

    public bool IsAuthenticated => _currentAuth?.IsSuccess == true && 
                                 _currentAuth.ExpiresAt > DateTime.UtcNow.AddMinutes(1);

    public string? CurrentUsername => _currentAuth?.Username;
    public string? CurrentAccessToken => _currentAuth?.AccessToken;
    public DateTime? TokenExpiresAt => _currentAuth?.ExpiresAt;

    public AuthenticationService(IConfigurationService configurationService, HttpClient httpClient, ILogger<AuthenticationService>? logger = null)
    {
        _configurationService = configurationService;
        _httpClient = httpClient;
        _logger = logger;
        
        LoadStoredAuthentication();
    }

    public async Task<AuthenticationResult> AuthenticateAsync(string backendUrl, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger?.LogInformation("Starting OAuth 2.0 PKCE authentication for backend: {BackendUrl}", backendUrl);
            
            // Get OAuth configuration from backend
            _oauthConfig = await GetOAuthConfigurationAsync(backendUrl, cancellationToken);
            if (_oauthConfig == null)
            {
                return new AuthenticationResult
                {
                    IsSuccess = false,
                    ErrorMessage = "Failed to retrieve OAuth configuration from backend"
                };
            }

            // Generate PKCE parameters
            var pkce = GeneratePkceParameters();
            
            // Start local callback listener
            var callbackTask = StartCallbackListenerAsync(pkce, cancellationToken);
            
            // Open browser for authorization
            var authUrl = BuildAuthorizationUrl(_oauthConfig, pkce);
            OpenBrowser(authUrl);
            
            // Wait for callback or timeout
            var result = await callbackTask;
            
            if (result.IsSuccess)
            {
                // Store authentication securely
                await StoreAuthenticationAsync(result);
                _currentAuth = result;
                AuthenticationCompleted?.Invoke(this, result);
            }
            
            return result;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Authentication failed");
            return new AuthenticationResult
            {
                IsSuccess = false,
                ErrorMessage = ex.Message
            };
        }
    }

    public async Task<AuthenticationResult> RefreshTokenAsync(CancellationToken cancellationToken = default)
    {
        if (_currentAuth?.RefreshToken == null || _oauthConfig == null)
        {
            return new AuthenticationResult
            {
                IsSuccess = false,
                ErrorMessage = "No refresh token available"
            };
        }

        try
        {
            var tokenRequest = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = _currentAuth.RefreshToken,
                ["client_id"] = _oauthConfig.ClientId
            };

            var response = await _httpClient.PostAsync(_oauthConfig.TokenEndpoint, 
                new FormUrlEncodedContent(tokenRequest), cancellationToken);

            if (response.IsSuccessStatusCode)
            {
                var tokenInfo = await response.Content.ReadFromJsonAsync<TokenInfo>(cancellationToken: cancellationToken);
                if (tokenInfo != null && !string.IsNullOrEmpty(tokenInfo.AccessToken))
                {
                    var result = new AuthenticationResult
                    {
                        IsSuccess = true,
                        AccessToken = tokenInfo.AccessToken,
                        RefreshToken = tokenInfo.RefreshToken ?? _currentAuth.RefreshToken,
                        ExpiresAt = DateTime.UtcNow.AddSeconds(tokenInfo.ExpiresIn),
                        Username = _currentAuth.Username,
                        Email = _currentAuth.Email,
                        Scopes = _currentAuth.Scopes
                    };

                    await StoreAuthenticationAsync(result);
                    _currentAuth = result;
                    return result;
                }
            }

            return new AuthenticationResult
            {
                IsSuccess = false,
                ErrorMessage = "Failed to refresh token"
            };
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Token refresh failed");
            return new AuthenticationResult
            {
                IsSuccess = false,
                ErrorMessage = ex.Message
            };
        }
    }

    public Task LogoutAsync()
    {
        // Clear stored authentication
        _configurationService.ClearSecureString("access_token");
        _configurationService.ClearSecureString("refresh_token");
        _configurationService.ClearSecureString("user_info");
        
        _currentAuth = null;
        _oauthConfig = null;
        
        _logger?.LogInformation("User logged out");
        
        return Task.CompletedTask;
    }

    private async Task<OAuthConfiguration?> GetOAuthConfigurationAsync(string backendUrl, CancellationToken cancellationToken)
    {
        try
        {
            var configUrl = $"{backendUrl.TrimEnd('/')}/api/auth/config";
            var response = await _httpClient.GetAsync(configUrl, cancellationToken);
            
            if (response.IsSuccessStatusCode)
            {
                var backendInfo = await response.Content.ReadFromJsonAsync<BackendInfo>(cancellationToken: cancellationToken);
                return backendInfo?.OAuth;
            }
            
            // Fallback to default configuration for testing
            return new OAuthConfiguration
            {
                ClientId = "ironveil-desktop",
                AuthorizationEndpoint = $"{backendUrl}/auth/authorize",
                TokenEndpoint = $"{backendUrl}/auth/token",
                UserInfoEndpoint = $"{backendUrl}/auth/userinfo",
                Scopes = new List<string> { "openid", "profile", "email", "scan:upload" }
            };
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to get OAuth configuration");
            return null;
        }
    }

    private PkceParameters GeneratePkceParameters()
    {
        var codeVerifier = GenerateRandomBase64UrlString(128);
        var codeChallenge = ComputeCodeChallenge(codeVerifier);
        var state = GenerateRandomBase64UrlString(32);
        var nonce = GenerateRandomBase64UrlString(32);

        return new PkceParameters
        {
            CodeVerifier = codeVerifier,
            CodeChallenge = codeChallenge,
            State = state,
            Nonce = nonce
        };
    }

    private string GenerateRandomBase64UrlString(int length)
    {
        var bytes = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .Replace("=", "");
    }

    private string ComputeCodeChallenge(string codeVerifier)
    {
        using var sha256 = SHA256.Create();
        var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
        return Convert.ToBase64String(challengeBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .Replace("=", "");
    }

    private string BuildAuthorizationUrl(OAuthConfiguration config, PkceParameters pkce)
    {
        var queryParams = HttpUtility.ParseQueryString(string.Empty);
        queryParams["response_type"] = "code";
        queryParams["client_id"] = config.ClientId;
        queryParams["redirect_uri"] = config.RedirectUri;
        queryParams["scope"] = string.Join(" ", config.Scopes);
        queryParams["state"] = pkce.State;
        queryParams["code_challenge"] = pkce.CodeChallenge;
        queryParams["code_challenge_method"] = "S256";
        queryParams["nonce"] = pkce.Nonce;

        return $"{config.AuthorizationEndpoint}?{queryParams}";
    }

    private async Task<AuthenticationResult> StartCallbackListenerAsync(PkceParameters pkce, CancellationToken cancellationToken)
    {
        _callbackListener = new HttpListener();
        _callbackListener.Prefixes.Add($"http://localhost:{_oauthConfig!.CallbackPort}/");
        _callbackListener.Start();

        try
        {
            using var registration = cancellationToken.Register(() => _callbackListener?.Stop());
            
            var context = await _callbackListener.GetContextAsync();
            var request = context.Request;
            var response = context.Response;

            // Send response to browser
            var responseString = "<html><body><h1>Authentication Complete</h1><p>You can close this window.</p></body></html>";
            var buffer = Encoding.UTF8.GetBytes(responseString);
            response.ContentLength64 = buffer.Length;
            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length, cancellationToken);
            response.OutputStream.Close();

            // Parse callback parameters
            var query = HttpUtility.ParseQueryString(request.Url?.Query ?? "");
            var code = query["code"];
            var state = query["state"];
            var error = query["error"];

            if (!string.IsNullOrEmpty(error))
            {
                return new AuthenticationResult
                {
                    IsSuccess = false,
                    ErrorMessage = query["error_description"] ?? error
                };
            }

            if (state != pkce.State)
            {
                return new AuthenticationResult
                {
                    IsSuccess = false,
                    ErrorMessage = "Invalid state parameter"
                };
            }

            if (string.IsNullOrEmpty(code))
            {
                return new AuthenticationResult
                {
                    IsSuccess = false,
                    ErrorMessage = "No authorization code received"
                };
            }

            // Exchange code for tokens
            return await ExchangeCodeForTokensAsync(code, pkce, cancellationToken);
        }
        finally
        {
            _callbackListener?.Stop();
            _callbackListener = null;
        }
    }

    private async Task<AuthenticationResult> ExchangeCodeForTokensAsync(string code, PkceParameters pkce, CancellationToken cancellationToken)
    {
        var tokenRequest = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = _oauthConfig!.RedirectUri,
            ["client_id"] = _oauthConfig.ClientId,
            ["code_verifier"] = pkce.CodeVerifier
        };

        var response = await _httpClient.PostAsync(_oauthConfig.TokenEndpoint, 
            new FormUrlEncodedContent(tokenRequest), cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
            return new AuthenticationResult
            {
                IsSuccess = false,
                ErrorMessage = $"Token exchange failed: {errorContent}"
            };
        }

        var tokenInfo = await response.Content.ReadFromJsonAsync<TokenInfo>(cancellationToken: cancellationToken);
        if (tokenInfo == null || string.IsNullOrEmpty(tokenInfo.AccessToken))
        {
            return new AuthenticationResult
            {
                IsSuccess = false,
                ErrorMessage = "Invalid token response"
            };
        }

        // Get user info
        var userInfo = await GetUserInfoAsync(tokenInfo.AccessToken, cancellationToken);

        return new AuthenticationResult
        {
            IsSuccess = true,
            AccessToken = tokenInfo.AccessToken,
            RefreshToken = tokenInfo.RefreshToken,
            ExpiresAt = DateTime.UtcNow.AddSeconds(tokenInfo.ExpiresIn),
            Username = userInfo?.Name ?? userInfo?.Email ?? "Unknown",
            Email = userInfo?.Email,
            Scopes = tokenInfo.Scope?.Split(' ').ToList() ?? new List<string>()
        };
    }

    private async Task<UserInfo?> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, _oauthConfig!.UserInfoEndpoint);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadFromJsonAsync<UserInfo>(cancellationToken: cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to get user info");
        }
        
        return null;
    }

    private void OpenBrowser(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to open browser");
            throw new InvalidOperationException($"Failed to open browser: {ex.Message}");
        }
    }

    private Task StoreAuthenticationAsync(AuthenticationResult result)
    {
        if (result.AccessToken != null)
        {
            _configurationService.SetSecureString("access_token", result.AccessToken);
        }
        
        if (result.RefreshToken != null)
        {
            _configurationService.SetSecureString("refresh_token", result.RefreshToken);
        }

        var userInfo = new
        {
            Username = result.Username,
            Email = result.Email,
            ExpiresAt = result.ExpiresAt,
            Scopes = result.Scopes
        };
        
        _configurationService.SetSecureString("user_info", JsonSerializer.Serialize(userInfo));
        
        return Task.CompletedTask;
    }

    private void LoadStoredAuthentication()
    {
        try
        {
            var accessToken = _configurationService.GetSecureString("access_token");
            var refreshToken = _configurationService.GetSecureString("refresh_token");
            var userInfoJson = _configurationService.GetSecureString("user_info");

            if (!string.IsNullOrEmpty(accessToken) && !string.IsNullOrEmpty(userInfoJson))
            {
                var userInfo = JsonSerializer.Deserialize<Dictionary<string, object>>(userInfoJson);
                if (userInfo != null)
                {
                    _currentAuth = new AuthenticationResult
                    {
                        IsSuccess = true,
                        AccessToken = accessToken,
                        RefreshToken = refreshToken,
                        Username = userInfo.GetValueOrDefault("Username")?.ToString(),
                        Email = userInfo.GetValueOrDefault("Email")?.ToString(),
                        ExpiresAt = userInfo.ContainsKey("ExpiresAt") && DateTime.TryParse(userInfo["ExpiresAt"].ToString(), out var expires) ? expires : null
                    };
                }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to load stored authentication");
        }
    }

    public void Dispose()
    {
        _callbackListener?.Stop();
        _callbackListener = null;
        _httpClient?.Dispose();
    }
}