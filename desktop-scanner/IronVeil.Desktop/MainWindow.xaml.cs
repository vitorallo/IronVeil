using System.Diagnostics;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;
using IronVeil.Core.Models;
using IronVeil.Core.Services;
using IronVeil.Desktop.Services;
using IronVeil.PowerShell;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using System.IO;

namespace IronVeil.Desktop;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    private readonly IAuthenticationService _authenticationService;
    private readonly IApiClient _apiClient;
    private readonly IPowerShellExecutor _powerShellExecutor;
    private readonly IConfigurationService _configurationService;
    private readonly ISystemRequirementsService _systemRequirementsService;
    private readonly ILogger<MainWindow>? _logger;
    
    private bool _isAuthenticated = false;
    private ScanSession? _currentScanSession;
    private CancellationTokenSource? _scanCancellationSource;
    private SystemRequirements? _systemRequirements;

    public MainWindow()
    {
        InitializeComponent();
        
        // Get services from DI container
        _authenticationService = ServiceProvider.GetRequiredService<IAuthenticationService>();
        _apiClient = ServiceProvider.GetRequiredService<IApiClient>();
        _powerShellExecutor = ServiceProvider.GetRequiredService<IPowerShellExecutor>();
        _configurationService = ServiceProvider.GetRequiredService<IConfigurationService>();
        _systemRequirementsService = ServiceProvider.GetRequiredService<ISystemRequirementsService>();
        _logger = ServiceProvider.GetService<ILogger<MainWindow>>();
        
        InitializeApplication();
    }

    private async void InitializeApplication()
    {
        try
        {
            // Set up event handlers
            _authenticationService.AuthenticationCompleted += OnAuthenticationCompleted;
            _powerShellExecutor.ProgressChanged += OnScanProgressChanged;
            _powerShellExecutor.RuleStarted += OnRuleStarted;
            _powerShellExecutor.RuleCompleted += OnRuleCompleted;
            _powerShellExecutor.RuleError += OnRuleError;
            
            // Load configuration
            LoadConfiguration();
            
            // Check system requirements
            await CheckSystemRequirementsAsync();
            
            // Set initial UI state
            UpdateAuthenticationStatus(_authenticationService.IsAuthenticated, _authenticationService.CurrentUsername);
            BackendSelector.SelectionChanged += BackendSelector_SelectionChanged;
            
            _logger?.LogInformation("Application initialized successfully");
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to initialize application");
            MessageBox.Show($"Failed to initialize application: {ex.Message}", "Initialization Error", 
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void UpdateAuthenticationStatus(bool isAuthenticated, string? username = null)
    {
        _isAuthenticated = isAuthenticated;
        
        if (isAuthenticated)
        {
            AuthStatusText.Text = "Authenticated";
            AuthUserText.Text = username ?? "user@organization.com";
            LoginButton.Content = "Logout";
            StartScanButton.IsEnabled = true;
            OpenDashboardButton.IsEnabled = true;
        }
        else
        {
            AuthStatusText.Text = "Not Authenticated";
            AuthUserText.Text = "Please login to continue";
            LoginButton.Content = "Login";
            StartScanButton.IsEnabled = false;
            OpenDashboardButton.IsEnabled = false;
        }
        
        // Update status bar
        StatusBarText.Text = isAuthenticated ? "Connected to backend" : "Ready";
    }

    private void BackendSelector_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (BackendSelector.SelectedIndex == 2) // Custom Backend option
        {
            // TODO: Show custom backend dialog
            MessageBox.Show("Custom backend configuration will be available in the next release.", 
                          "Coming Soon", MessageBoxButton.OK, MessageBoxImage.Information);
            BackendSelector.SelectedIndex = 0; // Reset to default
        }
        
        // Save backend selection
        var selectedUrl = GetSelectedBackendUrl();
        _configurationService.Configuration.Backend.LastUsedBackend = selectedUrl;
        _configurationService.SaveConfiguration();
        
        // Update API client
        _apiClient.CurrentBackendUrl = selectedUrl;
        
        // Reset authentication when backend changes
        if (_isAuthenticated)
        {
            _ = _authenticationService.LogoutAsync();
            UpdateAuthenticationStatus(false);
        }
    }

    private async void LoginButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isAuthenticated)
        {
            // Logout
            await _authenticationService.LogoutAsync();
            UpdateAuthenticationStatus(false);
            StatusBarText.Text = "Logged out successfully";
        }
        else
        {
            // Start OAuth 2.0 PKCE authentication flow
            LoginButton.IsEnabled = false;
            LoginButton.Content = "Authenticating...";
            StatusBarText.Text = "Opening browser for authentication...";
            
            try
            {
                var backendUrl = GetSelectedBackendUrl();
                _apiClient.CurrentBackendUrl = backendUrl;
                
                var result = await _authenticationService.AuthenticateAsync(backendUrl);
                
                if (result.IsSuccess)
                {
                    UpdateAuthenticationStatus(true, result.Username);
                    StatusBarText.Text = "Authentication successful";
                }
                else
                {
                    UpdateAuthenticationStatus(false);
                    StatusBarText.Text = "Authentication failed";
                    MessageBox.Show($"Authentication failed: {result.ErrorMessage}", 
                        "Authentication Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Authentication error");
                UpdateAuthenticationStatus(false);
                StatusBarText.Text = "Authentication error";
                MessageBox.Show($"Authentication error: {ex.Message}", 
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                LoginButton.IsEnabled = true;
                LoginButton.Content = _isAuthenticated ? "Logout" : "Login";
            }
        }
    }

    private void StartScanButton_Click(object sender, RoutedEventArgs e)
    {
        // Validate at least one scan type is selected
        if (!ScanADCheckbox.IsChecked.GetValueOrDefault() && 
            !ScanEntraCheckbox.IsChecked.GetValueOrDefault() && 
            !ScanHybridCheckbox.IsChecked.GetValueOrDefault())
        {
            MessageBox.Show("Please select at least one scan type.", "Configuration Error", 
                          MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        
        // Start scan
        StartScan();
    }

    private async void StartScan()
    {
        // Update UI state
        StartScanButton.IsEnabled = false;
        WelcomePanel.Visibility = Visibility.Collapsed;
        ResultsPanel.Visibility = Visibility.Collapsed;
        ProgressPanel.Visibility = Visibility.Visible;
        
        ScanProgressBar.Value = 0;
        ProgressStatusText.Text = "Initializing scanner...";
        ProgressDetailsText.Text = "Preparing PowerShell environment";
        StatusBarText.Text = "Scanning in progress...";
        
        try
        {
            // Create scan configuration from UI
            var config = new ScanConfiguration
            {
                ScanActiveDirectory = ScanADCheckbox.IsChecked == true,
                ScanEntraId = ScanEntraCheckbox.IsChecked == true,
                ScanHybridIdentity = ScanHybridCheckbox.IsChecked == true,
                MaxParallelRules = _configurationService.Configuration.Scan.MaxParallelRules,
                RuleTimeoutSeconds = _configurationService.Configuration.Scan.RuleTimeoutSeconds
            };
            
            // Start scan
            _scanCancellationSource = new CancellationTokenSource();
            _currentScanSession = await _powerShellExecutor.ExecuteScanAsync(config, _scanCancellationSource.Token);
            
            // Show results
            ShowScanResults();
        }
        catch (OperationCanceledException)
        {
            ProgressStatusText.Text = "Scan cancelled";
            StatusBarText.Text = "Scan cancelled by user";
            StartScanButton.IsEnabled = true;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Scan execution failed");
            ProgressStatusText.Text = "Scan failed";
            StatusBarText.Text = "Scan failed - see logs for details";
            MessageBox.Show($"Scan failed: {ex.Message}", "Scan Error", 
                MessageBoxButton.OK, MessageBoxImage.Error);
            StartScanButton.IsEnabled = true;
        }
    }


    private async void ShowScanResults()
    {
        ProgressPanel.Visibility = Visibility.Collapsed;
        ResultsPanel.Visibility = Visibility.Visible;
        StartScanButton.IsEnabled = true;
        ExportResultsButton.Visibility = Visibility.Visible;
        ExportResultsButton.IsEnabled = true;
        
        if (_currentScanSession == null) return;
        
        // Calculate severity counts
        var criticalCount = _currentScanSession.Results.Count(r => r.Severity == "Critical");
        var highCount = _currentScanSession.Results.Count(r => r.Severity == "High");
        var mediumCount = _currentScanSession.Results.Count(r => r.Severity == "Medium");
        var lowCount = _currentScanSession.Results.Count(r => r.Severity == "Low");
        
        CriticalCount.Text = criticalCount.ToString();
        HighCount.Text = highCount.ToString();
        MediumCount.Text = mediumCount.ToString();
        LowCount.Text = lowCount.ToString();
        
        // Show findings
        FindingsList.Items.Clear();
        foreach (var result in _currentScanSession.Results.Where(r => r.Findings.Any()).Take(20)) // Show top 20 findings
        {
            var finding = result.Findings.First();
            FindingsList.Items.Add(CreateFindingItem(result.Severity, finding.Description));
        }
        
        StatusBarText.Text = $"Scan completed: {_currentScanSession.Results.Count} results";
        
        // Auto-upload results if enabled
        if (_configurationService.Configuration.Security.AutoUploadResults && _isAuthenticated)
        {
            await UploadScanResultsAsync();
        }
    }

    private Border CreateFindingItem(string severity, string description)
    {
        var border = new Border
        {
            BorderThickness = new Thickness(0, 0, 0, 1),
            BorderBrush = new SolidColorBrush(Color.FromRgb(226, 232, 240)),
            Padding = new Thickness(10, 8, 10, 8)
        };
        
        var stack = new StackPanel { Orientation = Orientation.Horizontal };
        
        // Severity indicator
        var severityBlock = new TextBlock
        {
            Text = severity,
            FontWeight = FontWeights.SemiBold,
            Width = 70,
            Foreground = severity switch
            {
                "Critical" => new SolidColorBrush(Color.FromRgb(220, 38, 38)),
                "High" => new SolidColorBrush(Color.FromRgb(234, 88, 12)),
                "Medium" => new SolidColorBrush(Color.FromRgb(245, 158, 11)),
                _ => new SolidColorBrush(Color.FromRgb(34, 197, 94))
            }
        };
        
        var descBlock = new TextBlock
        {
            Text = description,
            Foreground = new SolidColorBrush(Color.FromRgb(30, 41, 59))
        };
        
        stack.Children.Add(severityBlock);
        stack.Children.Add(descBlock);
        border.Child = stack;
        
        return border;
    }

    private void LoadConfiguration()
    {
        var config = _configurationService.Configuration;
        
        // Set scan checkboxes
        ScanADCheckbox.IsChecked = config.Scan.ScanActiveDirectory;
        ScanEntraCheckbox.IsChecked = config.Scan.ScanEntraId;
        ScanHybridCheckbox.IsChecked = config.Scan.ScanHybridIdentity;
        
        // Set backend selection
        if (!string.IsNullOrEmpty(config.Backend.LastUsedBackend))
        {
            if (config.Backend.LastUsedBackend.Contains("enterprise"))
            {
                BackendSelector.SelectedIndex = 1;
            }
            else
            {
                BackendSelector.SelectedIndex = 0;
            }
        }
    }

    private string GetSelectedBackendUrl()
    {
        return BackendSelector.SelectedIndex switch
        {
            1 => "https://enterprise.ironveil.io",
            _ => "https://ironveil.crimson7.io"
        };
    }

    private void OnAuthenticationCompleted(object? sender, AuthenticationResult result)
    {
        Dispatcher.Invoke(() =>
        {
            UpdateAuthenticationStatus(result.IsSuccess, result.Username);
            StatusBarText.Text = result.IsSuccess ? "Authentication completed" : "Authentication failed";
        });
    }

    private void OnScanProgressChanged(object? sender, ScanProgressEventArgs e)
    {
        Dispatcher.Invoke(() =>
        {
            ScanProgressBar.Value = e.Progress;
            ProgressStatusText.Text = $"Processing rules ({e.CompletedRules}/{e.TotalRules})";
            ProgressDetailsText.Text = $"Current: {e.CurrentRule}";
        });
    }

    private void OnRuleStarted(object? sender, RuleExecutionEventArgs e)
    {
        Dispatcher.Invoke(() =>
        {
            ProgressDetailsText.Text = $"Executing: {e.RuleName}";
        });
    }

    private void OnRuleCompleted(object? sender, RuleExecutionEventArgs e)
    {
        // This is handled by OnScanProgressChanged
    }

    private void OnRuleError(object? sender, RuleExecutionEventArgs e)
    {
        _logger?.LogWarning("Rule {RuleName} failed: {Error}", e.RuleName, e.Error);
    }

    private async Task UploadScanResultsAsync()
    {
        if (_currentScanSession == null || !_isAuthenticated) return;

        try
        {
            StatusBarText.Text = "Uploading scan results...";

            var uploadRequest = new ScanUploadRequest
            {
                SessionId = _currentScanSession.SessionId,
                Results = _currentScanSession.Results,
                Configuration = _currentScanSession.Configuration,
                Metadata = new UploadMetadata
                {
                    ScannerVersion = "1.0.0",
                    Platform = "Windows",
                    TotalRules = _currentScanSession.Results.Count,
                    SuccessfulRules = _currentScanSession.Results.Count(r => r.Status == "Success"),
                    FailedRules = _currentScanSession.Results.Count(r => r.Status == "Failed" || r.Status == "Error"),
                    Duration = (_currentScanSession.EndTime - _currentScanSession.StartTime)?.TotalSeconds ?? 0
                }
            };

            var response = await _apiClient.UploadScanResultsAsync(uploadRequest);

            if (response.Success)
            {
                StatusBarText.Text = "Results uploaded successfully";
                _logger?.LogInformation("Scan results uploaded successfully. Upload ID: {UploadId}", response.Data?.UploadId);
            }
            else
            {
                StatusBarText.Text = "Upload failed - results saved locally";
                _logger?.LogWarning("Failed to upload scan results: {Error}", response.Error);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error uploading scan results");
            StatusBarText.Text = "Upload error - results saved locally";
        }
    }

    private void OpenDashboardButton_Click(object sender, RoutedEventArgs e)
    {
        var backendUrl = BackendSelector.SelectedIndex == 0 
            ? "https://ironveil.crimson7.io" 
            : "https://enterprise.ironveil.io";
            
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = backendUrl,
                UseShellExecute = true
            });
            StatusBarText.Text = "Opening dashboard in browser...";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to open dashboard: {ex.Message}", "Error", 
                          MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void ExportResultsButton_Click(object sender, RoutedEventArgs e)
    {
        if (_currentScanSession == null)
        {
            MessageBox.Show("No scan results to export.", "Export", 
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        
        try
        {
            // Show save file dialog
            var saveDialog = new Microsoft.Win32.SaveFileDialog
            {
                FileName = $"IronVeil_Scan_{DateTime.Now:yyyyMMdd_HHmmss}.json",
                DefaultExt = ".json",
                Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
            };
            
            if (saveDialog.ShowDialog() == true)
            {
                // Create upload request structure for export
                var uploadRequest = new ScanUploadRequest
                {
                    SessionId = _currentScanSession.SessionId,
                    Results = _currentScanSession.Results,
                    Configuration = _currentScanSession.Configuration,
                    Metadata = new UploadMetadata
                    {
                        ScannerVersion = "1.0.0",
                        Platform = "Windows",
                        TotalRules = _currentScanSession.Results.Count,
                        SuccessfulRules = _currentScanSession.Results.Count(r => r.Status == "Success"),
                        FailedRules = _currentScanSession.Results.Count(r => r.Status == "Failed" || r.Status == "Error"),
                        Duration = (_currentScanSession.EndTime - _currentScanSession.StartTime)?.TotalSeconds ?? 0
                    }
                };
                
                var json = JsonSerializer.Serialize(uploadRequest, new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });
                
                await File.WriteAllTextAsync(saveDialog.FileName, json);
                
                MessageBox.Show($"Scan results exported to {saveDialog.FileName}", "Export Complete", 
                    MessageBoxButton.OK, MessageBoxImage.Information);
                StatusBarText.Text = "Results exported successfully";
                
                _logger?.LogInformation("Scan results exported to {FileName}", saveDialog.FileName);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to export scan results");
            MessageBox.Show($"Failed to export results: {ex.Message}", "Export Error", 
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task CheckSystemRequirementsAsync()
    {
        try
        {
            _systemRequirements = await _systemRequirementsService.CheckRequirementsAsync();
            UpdateSystemRequirementsUI();
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to check system requirements");
            PowerShellStatusText.Text = "PowerShell: Error checking";
            DomainStatusText.Text = "Domain: Error checking";
            AdminStatusText.Text = "Admin Rights: Error checking";
        }
    }

    private void UpdateSystemRequirementsUI()
    {
        if (_systemRequirements == null) return;

        // Update PowerShell status
        if (_systemRequirements.PowerShellAvailable)
        {
            PowerShellStatusIndicator.Fill = new SolidColorBrush(Colors.Green);
            PowerShellStatusText.Text = $"PowerShell: {_systemRequirements.PowerShellVersion}";
        }
        else
        {
            PowerShellStatusIndicator.Fill = new SolidColorBrush(Colors.Red);
            PowerShellStatusText.Text = "PowerShell: Not Available";
        }

        // Update domain status
        if (_systemRequirements.IsDomainJoined)
        {
            DomainStatusIndicator.Fill = new SolidColorBrush(Colors.Green);
            DomainStatusText.Text = $"Domain: {_systemRequirements.CurrentDomain ?? "Joined"}";
            
            // Populate domain selector
            DomainSelector.Items.Clear();
            foreach (var domain in _systemRequirements.AvailableDomains)
            {
                var item = new ComboBoxItem { Content = domain };
                if (domain == _systemRequirements.CurrentDomain)
                {
                    item.IsSelected = true;
                }
                DomainSelector.Items.Add(item);
            }
            DomainSelector.IsEnabled = _systemRequirements.AvailableDomains.Count > 1;
            
            if (_systemRequirements.AvailableDomains.Count > 1)
            {
                DomainInfoText.Text = $"{_systemRequirements.AvailableDomains.Count} domains available in forest";
            }
        }
        else
        {
            DomainStatusIndicator.Fill = new SolidColorBrush(Colors.Orange);
            DomainStatusText.Text = "Domain: Not Joined";
            DomainSelector.Items.Clear();
            DomainSelector.Items.Add(new ComboBoxItem { Content = "Local Computer Only", IsSelected = true });
            DomainSelector.IsEnabled = false;
            DomainInfoText.Text = "Active Directory scans unavailable";
        }

        // Update admin status
        if (_systemRequirements.IsAdministrator)
        {
            AdminStatusIndicator.Fill = new SolidColorBrush(Colors.Green);
            AdminStatusText.Text = "Admin Rights: Elevated";
        }
        else
        {
            AdminStatusIndicator.Fill = new SolidColorBrush(Colors.Orange);
            AdminStatusText.Text = "Admin Rights: Standard User";
        }

        // Update scan checkboxes based on requirements
        ScanADCheckbox.IsEnabled = _systemRequirements.CanRunActiveDirectoryScans;
        if (!_systemRequirements.CanRunActiveDirectoryScans)
        {
            ScanADCheckbox.IsChecked = false;
        }

        ScanEntraCheckbox.IsEnabled = _systemRequirements.CanRunEntraIdScans;
        ScanHybridCheckbox.IsEnabled = _systemRequirements.CanRunActiveDirectoryScans && _systemRequirements.CanRunEntraIdScans;
        
        if (!_systemRequirements.CanRunActiveDirectoryScans || !_systemRequirements.CanRunEntraIdScans)
        {
            ScanHybridCheckbox.IsChecked = false;
        }

        // Show issues panel if there are any
        var issues = _systemRequirements.GetIssues();
        if (issues.Any())
        {
            SystemIssuesPanel.Visibility = Visibility.Visible;
            SystemIssuesList.ItemsSource = issues;
        }
        else
        {
            SystemIssuesPanel.Visibility = Visibility.Collapsed;
        }

        // Update start scan button
        if (!_systemRequirements.PowerShellAvailable)
        {
            StartScanButton.IsEnabled = false;
            StartScanButton.ToolTip = "PowerShell is required to run scans";
        }
    }

    private async void RefreshStatusButton_Click(object sender, RoutedEventArgs e)
    {
        RefreshStatusButton.IsEnabled = false;
        PowerShellStatusText.Text = "PowerShell: Checking...";
        DomainStatusText.Text = "Domain: Checking...";
        AdminStatusText.Text = "Admin Rights: Checking...";
        
        await CheckSystemRequirementsAsync();
        
        RefreshStatusButton.IsEnabled = true;
    }

    protected override void OnClosed(EventArgs e)
    {
        try
        {
            // Cancel any running scan
            _scanCancellationSource?.Cancel();
            
            // Unsubscribe from events
            if (_authenticationService != null)
            {
                _authenticationService.AuthenticationCompleted -= OnAuthenticationCompleted;
            }
            
            if (_powerShellExecutor != null)
            {
                _powerShellExecutor.ProgressChanged -= OnScanProgressChanged;
                _powerShellExecutor.RuleStarted -= OnRuleStarted;
                _powerShellExecutor.RuleCompleted -= OnRuleCompleted;
                _powerShellExecutor.RuleError -= OnRuleError;
                
                if (_powerShellExecutor is IDisposable disposable)
                {
                    disposable.Dispose();
                }
            }
            
            // Save configuration
            _configurationService?.SaveConfiguration();
            
            // Cleanup scan resources
            _scanCancellationSource?.Dispose();
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error during window cleanup");
        }
        
        base.OnClosed(e);
    }
}