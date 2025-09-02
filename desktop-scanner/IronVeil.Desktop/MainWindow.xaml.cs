using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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
using IronVeil.PowerShell.Models;
using IronVeil.PowerShell.Services;
using Microsoft.Extensions.Logging;
using System.Text.Json;

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
    private readonly IEntraIDAuthenticationManager _entraIdAuthManager;
    private readonly IRuleManifestService _ruleManifestService;
    private readonly ILogger<MainWindow>? _logger;
    
    private bool _isAuthenticated = false;
    private bool _isEntraIdAuthenticated = false;
    private ScanSession? _currentScanSession;
    private CancellationTokenSource? _scanCancellationSource;
    private SystemRequirements? _systemRequirements;
    private RuleManifest? _ruleManifest;
    private DateTime _scanStartTime;
    private int _totalRulesInScan;

    public MainWindow()
    {
        try
        {
            Console.WriteLine("MainWindow constructor started");
            InitializeComponent();
            Console.WriteLine("InitializeComponent completed");
            
            // Get services from DI container
            _authenticationService = ServiceProvider.GetRequiredService<IAuthenticationService>();
            _apiClient = ServiceProvider.GetRequiredService<IApiClient>();
            _powerShellExecutor = ServiceProvider.GetRequiredService<IPowerShellExecutor>();
            _configurationService = ServiceProvider.GetRequiredService<IConfigurationService>();
            _systemRequirementsService = ServiceProvider.GetRequiredService<ISystemRequirementsService>();
            _logger = ServiceProvider.GetService<ILogger<MainWindow>>();
            
            // Initialize new services
            _entraIdAuthManager = new EntraIDAuthenticationManager(_logger as ILogger<EntraIDAuthenticationManager>);
            _ruleManifestService = new RuleManifestService(_logger as ILogger<RuleManifestService>);
            
            Loaded += MainWindow_Loaded;
            Console.WriteLine("MainWindow constructor completed successfully");
        }
        catch (Exception ex)
        {
            // Log the error but don't show message box
            Console.WriteLine($"ERROR in MainWindow constructor: {ex.Message}");
            _logger?.LogError(ex, "Failed to initialize MainWindow");
            // Don't show error dialog - just continue
            // Initialize fields that might be null to prevent further errors
            _authenticationService = _authenticationService ?? ServiceProvider.GetService<IAuthenticationService>();
            _apiClient = _apiClient ?? ServiceProvider.GetService<IApiClient>();
            _powerShellExecutor = _powerShellExecutor ?? ServiceProvider.GetService<IPowerShellExecutor>();
            _configurationService = _configurationService ?? ServiceProvider.GetService<IConfigurationService>();
            _systemRequirementsService = _systemRequirementsService ?? ServiceProvider.GetService<ISystemRequirementsService>();
        }
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            // Initialize on UI thread to avoid cross-thread issues
            await InitializeApplicationAsync();
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed during application initialization");
            // Don't show error dialog - just update status
            StatusBarText.Text = "Ready (some features may be limited)";
        }
    }

    private async Task InitializeApplicationAsync()
    {
        try
        {
            // Set up event handlers (check for null first)
            if (_authenticationService != null)
                _authenticationService.AuthenticationCompleted += OnAuthenticationCompleted;
            if (_powerShellExecutor != null)
            {
                _powerShellExecutor.ProgressChanged += OnScanProgressChanged;
                _powerShellExecutor.RuleStarted += OnRuleStarted;
                _powerShellExecutor.RuleCompleted += OnRuleCompleted;
                _powerShellExecutor.RuleError += OnRuleError;
            }
            if (_entraIdAuthManager != null)
                _entraIdAuthManager.AuthenticationStateChanged += OnEntraIdAuthenticationStateChanged;
            
            // Load configuration
            LoadConfiguration();
            
            // Check system requirements in background with timeout
            _ = Task.Run(async () =>
            {
                try
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    await CheckSystemRequirementsAsync(cts.Token);
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "System requirements check failed or timed out");
                }
            });
            
            // Load rule manifest (needs to be on UI thread for MessageBox)
            try
            {
                await LoadRuleManifestAsync();
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to load rule manifest during initialization");
            }
            
            // Set initial UI state
            UpdateAuthenticationStatus(_authenticationService.IsAuthenticated, _authenticationService.CurrentUsername);
            UpdateEntraIdAuthenticationStatus(false);
            BackendSelector.SelectionChanged += BackendSelector_SelectionChanged;
            
            // Set up scan configuration change handlers
            ScanADCheckbox.Checked += OnScanConfigurationChanged;
            ScanADCheckbox.Unchecked += OnScanConfigurationChanged;
            ScanEntraCheckbox.Checked += OnScanConfigurationChanged;
            ScanEntraCheckbox.Unchecked += OnScanConfigurationChanged;
            Tier1Checkbox.Checked += OnScanConfigurationChanged;
            Tier1Checkbox.Unchecked += OnScanConfigurationChanged;
            Tier2Checkbox.Checked += OnScanConfigurationChanged;
            Tier2Checkbox.Unchecked += OnScanConfigurationChanged;
            Tier3Checkbox.Checked += OnScanConfigurationChanged;
            Tier3Checkbox.Unchecked += OnScanConfigurationChanged;
            Tier4Checkbox.Checked += OnScanConfigurationChanged;
            Tier4Checkbox.Unchecked += OnScanConfigurationChanged;
            
            _logger?.LogInformation("Application initialized successfully");
            StatusBarText.Text = "Ready";
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to initialize application");
            // Don't show message box - just log and continue
            StatusBarText.Text = "Ready";
        }
    }

    private async Task LoadRuleManifestAsync()
    {
        try
        {
            // Get the manifest path
            var manifestPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "indicators", "manifest.json");
            
            _logger?.LogInformation("Loading rule manifest from: {Path}", manifestPath);
            
            // Check if file exists
            if (!File.Exists(manifestPath))
            {
                throw new FileNotFoundException($"Manifest file not found at: {manifestPath}");
            }
            
            _ruleManifest = await _ruleManifestService.LoadManifestAsync(manifestPath);
            _logger?.LogInformation("Loaded rule manifest v{Version} with {RuleCount} rules", 
                _ruleManifest.Version, _ruleManifest.Rules.Count);
            
            // Log all loaded checks for development
            LogLoadedChecks();
            
            // Populate scan profile dropdown from manifest
            PopulateScanProfiles();
            
            // Update UI based on manifest
            await UpdateRuleCountPreview();
        }
        catch (FileNotFoundException fnfEx)
        {
            _logger?.LogError(fnfEx, "Manifest file not found");
            
            var message = $"Rule manifest file not found.\n\nExpected location:\n{fnfEx.Message}\n\n" +
                         "Please ensure the 'indicators' folder is present with manifest.json file.\n\n" +
                         "You can click 'Refresh' after fixing the issue.";
            
            // Show on UI thread
            await Dispatcher.InvokeAsync(() =>
            {
                MessageBox.Show(message, "Configuration Error - Manifest Not Found", 
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            });
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to load rule manifest");
            
            var message = $"Failed to load rule manifest:\n\n{ex.Message}\n\n" +
                         $"Error Type: {ex.GetType().Name}\n\n" +
                         "Check the application logs for more details.\n" +
                         "You can click 'Refresh' to retry loading.";
            
            // Show on UI thread
            await Dispatcher.InvokeAsync(() =>
            {
                MessageBox.Show(message, "Configuration Error - Manifest Load Failed", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            });
        }
    }

    private void LogLoadedChecks()
    {
        if (_ruleManifest == null) return;
        
        Console.WriteLine("\n" + new string('=', 80));
        Console.WriteLine("IRONVEIL SECURITY CHECKS - DEVELOPMENT LOG");
        Console.WriteLine(new string('=', 80));
        Console.WriteLine($"Manifest Version: {_ruleManifest.Version}");
        Console.WriteLine($"Last Updated: {_ruleManifest.LastUpdated}");
        Console.WriteLine($"Total Rules: {_ruleManifest.Rules.Count}");
        Console.WriteLine(new string('-', 80));
        
        // Group rules by tier
        var rulesByTier = _ruleManifest.Rules
            .GroupBy(r => r.Value.Tier)
            .OrderBy(g => _ruleManifest.Tiers[g.Key].Priority);
        
        foreach (var tierGroup in rulesByTier)
        {
            var tier = _ruleManifest.Tiers[tierGroup.Key];
            Console.WriteLine($"\nTIER {tierGroup.Key}: {tier.Name} - {tier.Description}");
            Console.WriteLine($"Priority: {tier.Priority} | Weight: {tier.Weight} | Color: {tier.Color}");
            Console.WriteLine(new string('-', 60));
            
            foreach (var rule in tierGroup.OrderBy(r => r.Key))
            {
                Console.WriteLine($"  [{rule.Key}] {rule.Value.Name}");
                Console.WriteLine($"    Category: {rule.Value.Category}");
                Console.WriteLine($"    Environment: {rule.Value.Environment}");
                Console.WriteLine($"    Est. Time: {rule.Value.EstimatedTime}s");
                Console.WriteLine($"    Auth Required: {rule.Value.RequiresAuthentication}");
                Console.WriteLine($"    Admin Required: {rule.Value.RequiresAdmin}");
                if (rule.Value.Dependencies?.Any() == true)
                {
                    Console.WriteLine($"    Dependencies: {string.Join(", ", rule.Value.Dependencies)}");
                }
                if (rule.Value.Frameworks?.Any() == true)
                {
                    Console.WriteLine($"    Frameworks: {string.Join(", ", rule.Value.Frameworks)}");
                }
                Console.WriteLine();
            }
        }
        
        // Log scan profiles
        Console.WriteLine(new string('=', 80));
        Console.WriteLine("SCAN PROFILES");
        Console.WriteLine(new string('-', 80));
        foreach (var profile in _ruleManifest.Profiles)
        {
            Console.WriteLine($"\n{profile.Key.ToUpper()}: {profile.Value.Name}");
            Console.WriteLine($"  Description: {profile.Value.Description}");
            Console.WriteLine($"  Tiers: {string.Join(", ", profile.Value.Tiers)}");
            Console.WriteLine($"  Estimated Rules: {profile.Value.EstimatedRules}");
            Console.WriteLine($"  Estimated Time: {profile.Value.EstimatedTime}");
        }
        
        // Log categories
        Console.WriteLine("\n" + new string('=', 80));
        Console.WriteLine("CATEGORIES");
        Console.WriteLine(new string('-', 80));
        foreach (var category in _ruleManifest.Categories)
        {
            var ruleCount = _ruleManifest.Rules.Count(r => r.Value.Category == category.Key);
            Console.WriteLine($"  {category.Key}: {category.Value} ({ruleCount} rules)");
        }
        
        // Log helper scripts
        if (_ruleManifest.HelperScripts?.Any() == true)
        {
            Console.WriteLine("\n" + new string('=', 80));
            Console.WriteLine("HELPER SCRIPTS");
            Console.WriteLine(new string('-', 80));
            foreach (var script in _ruleManifest.HelperScripts)
            {
                Console.WriteLine($"  {script.Key}: {script.Value.Description}");
                Console.WriteLine($"    Environment: {script.Value.Environment}");
                Console.WriteLine($"    Required: {script.Value.Required}");
            }
        }
        
        // Summary statistics
        Console.WriteLine("\n" + new string('=', 80));
        Console.WriteLine("SUMMARY STATISTICS");
        Console.WriteLine(new string('-', 80));
        
        var adRules = _ruleManifest.Rules.Count(r => r.Value.Environment == "ActiveDirectory");
        var entraIdRules = _ruleManifest.Rules.Count(r => r.Value.Environment == "EntraID");
        var authRequired = _ruleManifest.Rules.Count(r => r.Value.RequiresAuthentication);
        var adminRequired = _ruleManifest.Rules.Count(r => r.Value.RequiresAdmin);
        
        Console.WriteLine($"  Active Directory Rules: {adRules}");
        Console.WriteLine($"  Entra ID Rules: {entraIdRules}");
        Console.WriteLine($"  Rules Requiring Authentication: {authRequired}");
        Console.WriteLine($"  Rules Requiring Admin Rights: {adminRequired}");
        
        var totalEstTime = _ruleManifest.Rules.Sum(r => r.Value.EstimatedTime);
        Console.WriteLine($"  Total Estimated Time (all rules): {totalEstTime}s ({totalEstTime / 60:F1} minutes)");
        
        Console.WriteLine("\n" + new string('=', 80));
        Console.WriteLine("END OF DEVELOPMENT LOG");
        Console.WriteLine(new string('=', 80) + "\n");
        
        _logger?.LogDebug("Loaded {RuleCount} security checks from manifest", _ruleManifest.Rules.Count);
    }
    
    private async Task UpdateRuleCountPreview()
    {
        try
        {
            if (_ruleManifest == null)
            {
                RuleCountPreview.Text = "Estimated rules: Loading...";
                EstimatedTimeText.Text = "Est. time: Loading...";
                return;
            }

            var profileConfig = GetCurrentScanProfileConfiguration();
            
            // Count rules based on selected profile and environment filters
            var selectedTiers = profileConfig.SelectedTiers;
            var includeAD = profileConfig.IncludeActiveDirectory;
            var includeEntraID = profileConfig.IncludeEntraID;

            var eligibleRules = _ruleManifest.Rules.Values.Where(rule =>
            {
                // Check tier filter
                if (!selectedTiers.Contains(rule.Tier))
                    return false;

                // Check environment filter
                var isADRule = rule.Environment.Equals("ActiveDirectory", StringComparison.OrdinalIgnoreCase);
                var isEntraRule = rule.Environment.Equals("EntraID", StringComparison.OrdinalIgnoreCase);

                if (isADRule && !includeAD) return false;
                if (isEntraRule && !includeEntraID) return false;

                return true;
            });

            // Count executable rules (considering authentication requirements)
            var executableRules = eligibleRules.Where(rule =>
            {
                // If rule requires EntraID authentication, check if we're authenticated
                if (rule.RequiresAuthentication && rule.Environment.Equals("EntraID", StringComparison.OrdinalIgnoreCase))
                {
                    return _isEntraIdAuthenticated;
                }
                return true;
            }).Count();

            var totalEligible = eligibleRules.Count();
            
            // Update rule count display
            if (executableRules == totalEligible)
            {
                RuleCountPreview.Text = $"Selected rules: {executableRules}";
            }
            else
            {
                RuleCountPreview.Text = $"Selected rules: {executableRules} of {totalEligible} (some require authentication)";
            }

            // Update estimated time based on profile or calculate from selected rules
            var profileName = GetSelectedProfileName();
            if (profileName != "custom" && _ruleManifest.Profiles.TryGetValue(profileName, out var scanProfile))
            {
                EstimatedTimeText.Text = $"Est. time: {scanProfile.EstimatedTime}";
            }
            else
            {
                // Calculate estimated time based on selected rules (assuming ~15 seconds average per rule)
                var estimatedSeconds = executableRules * 15;
                var estimatedMinutes = Math.Max(1, estimatedSeconds / 60);
                EstimatedTimeText.Text = $"Est. time: {estimatedMinutes}-{estimatedMinutes + 2} minutes";
            }

            _logger?.LogDebug("Rule count preview updated: {ExecutableRules}/{TotalEligible} rules for profile {ProfileName}", 
                executableRules, totalEligible, profileName);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to update rule count preview");
            RuleCountPreview.Text = "Estimated rules: Error";
            EstimatedTimeText.Text = "Est. time: Unknown";
        }
    }

    private void PopulateScanProfiles()
    {
        if (_ruleManifest?.Profiles == null) return;

        try
        {
            // Store current selection
            var currentSelection = GetSelectedProfileName();
            
            // Clear existing items
            ScanProfileSelector.Items.Clear();
            
            // Add profiles from manifest
            foreach (var profile in _ruleManifest.Profiles.OrderBy(p => p.Key switch
            {
                "minimal" => 1,
                "recommended" => 2, 
                "full" => 3,
                _ => 4
            }))
            {
                var description = profile.Key switch
                {
                    "minimal" => $"Minimal ({profile.Value.Description ?? "Critical checks only"})",
                    "recommended" => $"Recommended ({profile.Value.Description ?? "Critical + High impact"})", 
                    "full" => $"Full ({profile.Value.Description ?? "All security checks"})",
                    _ => profile.Value.Description ?? profile.Key
                };

                var item = new ComboBoxItem
                {
                    Content = description,
                    Tag = profile.Key
                };
                
                ScanProfileSelector.Items.Add(item);
                
                // Restore selection if it matches
                if (profile.Key == currentSelection || (currentSelection == "recommended" && profile.Key == "recommended"))
                {
                    item.IsSelected = true;
                }
            }
            
            // Add Custom option
            var customItem = new ComboBoxItem
            {
                Content = "Custom (Manual tier selection)",
                Tag = "custom"
            };
            ScanProfileSelector.Items.Add(customItem);
            
            if (currentSelection == "custom")
            {
                customItem.IsSelected = true;
            }
            
            // If no selection was restored, default to recommended
            if (ScanProfileSelector.SelectedItem == null && ScanProfileSelector.Items.Count > 0)
            {
                var recommendedItem = ScanProfileSelector.Items.Cast<ComboBoxItem>()
                    .FirstOrDefault(i => i.Tag?.ToString() == "recommended");
                if (recommendedItem != null)
                {
                    recommendedItem.IsSelected = true;
                }
                else
                {
                    ((ComboBoxItem)ScanProfileSelector.Items[0]).IsSelected = true;
                }
            }
            
            _logger?.LogDebug("Populated scan profiles from manifest: {ProfileCount} profiles", _ruleManifest.Profiles.Count);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to populate scan profiles from manifest");
        }
    }

    private ScanProfileConfiguration GetCurrentScanProfileConfiguration()
    {
        var selectedTiers = new List<string>();
        var selectedProfile = GetSelectedProfileName();
        
        if (selectedProfile == "custom")
        {
            if (Tier1Checkbox.IsChecked == true) selectedTiers.Add("T1");
            if (Tier2Checkbox.IsChecked == true) selectedTiers.Add("T2");
            if (Tier3Checkbox.IsChecked == true) selectedTiers.Add("T3");
            if (Tier4Checkbox.IsChecked == true) selectedTiers.Add("T4");
        }
        else if (_ruleManifest?.Profiles.TryGetValue(selectedProfile, out var profile) == true)
        {
            selectedTiers.AddRange(profile.Tiers);
        }
        
        return new ScanProfileConfiguration
        {
            Type = selectedProfile switch
            {
                "minimal" => ScanProfileType.Minimal,
                "recommended" => ScanProfileType.Recommended,
                "full" => ScanProfileType.Full,
                _ => ScanProfileType.Custom
            },
            SelectedTiers = selectedTiers,
            IncludeActiveDirectory = ScanADCheckbox.IsChecked == true,
            IncludeEntraID = ScanEntraCheckbox.IsChecked == true,
            RequireAuthentication = _isEntraIdAuthenticated
        };
    }

    private string GetSelectedProfileName()
    {
        var selectedItem = ScanProfileSelector.SelectedItem as ComboBoxItem;
        return selectedItem?.Tag?.ToString() ?? "recommended";
    }

    private void UpdateEntraIdAuthenticationStatus(bool isAuthenticated, string? username = null, string? tenantId = null)
    {
        _isEntraIdAuthenticated = isAuthenticated;
        
        if (isAuthenticated)
        {
            EntraIDStatusIndicator.Fill = new SolidColorBrush(Colors.Green);
            EntraIDStatusText.Text = "Entra ID: Connected";
            EntraIDUserText.Text = username ?? "authenticated-user";
            ConnectEntraIDButton.Content = "Disconnect";
            ScanEntraCheckbox.IsEnabled = true;
            
            // Update hybrid checkbox based on both AD and Entra ID availability
            ScanHybridCheckbox.IsEnabled = _systemRequirements?.CanRunActiveDirectoryScans == true && isAuthenticated;
        }
        else
        {
            EntraIDStatusIndicator.Fill = new SolidColorBrush(Colors.Gray);
            EntraIDStatusText.Text = "Entra ID: Not Connected";
            EntraIDUserText.Text = "Connect to run Entra ID security checks";
            ConnectEntraIDButton.Content = "Connect";
            ScanEntraCheckbox.IsEnabled = false;
            ScanEntraCheckbox.IsChecked = false;
            ScanHybridCheckbox.IsEnabled = false;
            ScanHybridCheckbox.IsChecked = false;
        }
        
        // Update rule count preview
        _ = UpdateRuleCountPreview();
    }

    private void UpdateAuthenticationStatus(bool isAuthenticated, string? username = null)
    {
        _isAuthenticated = isAuthenticated;
        
        if (isAuthenticated)
        {
            AuthStatusText.Text = "Backend: Authenticated";
            AuthUserText.Text = username ?? "user@organization.com";
            LoginButton.Content = "Logout";
            StartScanButton.IsEnabled = true;
            OpenDashboardButton.IsEnabled = true;
        }
        else
        {
            AuthStatusText.Text = "Backend: Not Authenticated";
            AuthUserText.Text = "Login to upload results to cloud dashboard";
            LoginButton.Content = "Login";
            // Allow scanning without authentication for local-only mode
            StartScanButton.IsEnabled = true;
            StartScanButton.ToolTip = "You can scan locally. Login to upload results to the cloud dashboard.";
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

    private async void ConnectEntraIDButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isEntraIdAuthenticated)
        {
            // Disconnect
            await _entraIdAuthManager.DisconnectAsync();
            UpdateEntraIdAuthenticationStatus(false);
            StatusBarText.Text = "Disconnected from Entra ID";
        }
        else
        {
            // Connect
            ConnectEntraIDButton.IsEnabled = false;
            ConnectEntraIDButton.Content = "Connecting...";
            StatusBarText.Text = "Connecting to Entra ID...";
            
            try
            {
                var result = await _entraIdAuthManager.ConnectAsync();
                
                if (result.Success)
                {
                    UpdateEntraIdAuthenticationStatus(true, result.UserPrincipalName, result.TenantId);
                    StatusBarText.Text = "Connected to Entra ID successfully";
                    
                    // Enable Entra ID scan checkbox
                    ScanEntraCheckbox.IsEnabled = true;
                }
                else
                {
                    UpdateEntraIdAuthenticationStatus(false);
                    StatusBarText.Text = "Entra ID connection failed";
                    MessageBox.Show($"Failed to connect to Entra ID: {result.ErrorMessage}", 
                        "Authentication Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Entra ID connection error");
                UpdateEntraIdAuthenticationStatus(false);
                StatusBarText.Text = "Entra ID connection error";
                MessageBox.Show($"Error connecting to Entra ID: {ex.Message}", 
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ConnectEntraIDButton.IsEnabled = true;
                ConnectEntraIDButton.Content = _isEntraIdAuthenticated ? "Disconnect" : "Connect";
            }
        }
    }

    private void OnEntraIdAuthenticationStateChanged(object? sender, EntraIdAuthenticationEventArgs e)
    {
        Dispatcher.Invoke(() =>
        {
            UpdateEntraIdAuthenticationStatus(e.IsAuthenticated, e.UserPrincipalName, e.TenantId);
            StatusBarText.Text = e.IsAuthenticated ? "Entra ID connected" : "Entra ID disconnected";
        });
    }

    private async void ScanProfileSelector_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var selectedProfile = GetSelectedProfileName();
        
        // Show/hide tier selection panel and update tier checkboxes based on profile
        if (selectedProfile == "custom")
        {
            TierSelectionPanel.Visibility = Visibility.Visible;
            // For custom, keep current tier checkbox states
        }
        else
        {
            TierSelectionPanel.Visibility = Visibility.Collapsed;
            
            // Update tier checkboxes based on profile tiers from manifest
            if (_ruleManifest?.Profiles.TryGetValue(selectedProfile, out var profile) == true)
            {
                // Temporarily disable events to avoid recursion
                var originalHandlers = new Dictionary<CheckBox, RoutedEventHandler>();
                var checkboxes = new[] { Tier1Checkbox, Tier2Checkbox, Tier3Checkbox, Tier4Checkbox };
                
                foreach (var checkbox in checkboxes)
                {
                    checkbox.Checked -= OnScanConfigurationChanged;
                    checkbox.Unchecked -= OnScanConfigurationChanged;
                }

                // Set tier checkboxes based on profile
                Tier1Checkbox.IsChecked = profile.Tiers.Contains("T1");
                Tier2Checkbox.IsChecked = profile.Tiers.Contains("T2");
                Tier3Checkbox.IsChecked = profile.Tiers.Contains("T3");
                Tier4Checkbox.IsChecked = profile.Tiers.Contains("T4");

                // Re-enable events
                foreach (var checkbox in checkboxes)
                {
                    checkbox.Checked += OnScanConfigurationChanged;
                    checkbox.Unchecked += OnScanConfigurationChanged;
                }

                _logger?.LogDebug("Updated tier selection for profile {ProfileName}: {Tiers}", 
                    selectedProfile, string.Join(", ", profile.Tiers));
            }
        }
        
        await UpdateRuleCountPreview();
    }

    private async void OnScanConfigurationChanged(object sender, RoutedEventArgs e)
    {
        await UpdateRuleCountPreview();
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
        
        // Initialize progress display
        _scanStartTime = DateTime.Now;
        ScanProgressBar.Value = 0;
        ProgressStatusText.Text = "Initializing scanner...";
        ProgressPercentageText.Text = "0%";
        ProgressDetailsText.Text = "Loading rule manifest";
        ProgressTimeText.Text = "";
        CurrentRuleText.Text = "Preparing security checks...";
        StatusBarText.Text = "Scanning in progress...";
        
        try
        {
            // Create scan profile configuration from UI
            var profileConfig = GetCurrentScanProfileConfiguration();
            
            // Estimate total rules for progress calculation
            if (_ruleManifest != null)
            {
                var eligibleRules = _ruleManifest.Rules.Values.Where(rule =>
                {
                    if (!profileConfig.SelectedTiers.Contains(rule.Tier)) return false;
                    var isADRule = rule.Environment.Equals("ActiveDirectory", StringComparison.OrdinalIgnoreCase);
                    var isEntraRule = rule.Environment.Equals("EntraID", StringComparison.OrdinalIgnoreCase);
                    if (isADRule && !profileConfig.IncludeActiveDirectory) return false;
                    if (isEntraRule && !profileConfig.IncludeEntraID) return false;
                    if (rule.RequiresAuthentication && isEntraRule && !_isEntraIdAuthenticated) return false;
                    return true;
                });
                _totalRulesInScan = eligibleRules.Count();
                ProgressDetailsText.Text = $"Preparing to execute {_totalRulesInScan} security checks...";
            }
            
            _logger?.LogInformation("Starting scan with profile {ProfileType}, AD: {ScanAD}, EntraID: {ScanEntraID}, EstimatedRules: {RuleCount}", 
                profileConfig.Type, profileConfig.IncludeActiveDirectory, profileConfig.IncludeEntraID, _totalRulesInScan);
            
            // Start manifest-based scan
            _scanCancellationSource = new CancellationTokenSource();
            _currentScanSession = await _powerShellExecutor.ExecuteScanWithProfileAsync(
                profileConfig, 
                _entraIdAuthManager, 
                _scanCancellationSource.Token);
            
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
        finally
        {
            ProgressPanel.Visibility = Visibility.Collapsed;
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
        
        // Calculate FINDINGS counts (not rule counts) - count actual security issues found
        var allFindings = _currentScanSession.Results
            .Where(r => r.Status == "Success" && r.Findings != null)
            .SelectMany(r => r.Findings.Select(f => new { Result = r, Finding = f }))
            .ToList();
        
        var criticalFindings = allFindings.Count(f => f.Finding.RiskLevel == "Critical" || f.Result.Severity == "Critical");
        var highFindings = allFindings.Count(f => f.Finding.RiskLevel == "High" || (f.Finding.RiskLevel != "Critical" && f.Result.Severity == "High"));
        var mediumFindings = allFindings.Count(f => f.Finding.RiskLevel == "Medium" || (f.Finding.RiskLevel != "Critical" && f.Finding.RiskLevel != "High" && f.Result.Severity == "Medium"));
        var lowFindings = allFindings.Count(f => f.Finding.RiskLevel == "Low" || (f.Finding.RiskLevel != "Critical" && f.Finding.RiskLevel != "High" && f.Finding.RiskLevel != "Medium" && f.Result.Severity == "Low"));
        
        // If no findings were categorized by RiskLevel, fall back to counting by Result severity
        if (criticalFindings + highFindings + mediumFindings + lowFindings == 0 && allFindings.Any())
        {
            criticalFindings = allFindings.Count(f => f.Result.Severity == "Critical");
            highFindings = allFindings.Count(f => f.Result.Severity == "High");
            mediumFindings = allFindings.Count(f => f.Result.Severity == "Medium");
            lowFindings = allFindings.Count(f => f.Result.Severity == "Low");
        }
        
        CriticalCount.Text = criticalFindings.ToString();
        HighCount.Text = highFindings.ToString();
        MediumCount.Text = mediumFindings.ToString();
        LowCount.Text = lowFindings.ToString();
        
        // Show actual findings (security issues) not just rules
        FindingsList.Items.Clear();
        
        // Prioritize critical and high risk findings
        var findingsToShow = allFindings
            .OrderBy(f => f.Finding.RiskLevel == "Critical" ? 0 : 
                         f.Finding.RiskLevel == "High" ? 1 : 
                         f.Finding.RiskLevel == "Medium" ? 2 : 3)
            .ThenBy(f => f.Result.Severity == "Critical" ? 0 :
                        f.Result.Severity == "High" ? 1 :
                        f.Result.Severity == "Medium" ? 2 : 3)
            .Take(20);
        
        foreach (var item in findingsToShow)
        {
            var severity = item.Finding.RiskLevel ?? item.Result.Severity;
            var description = $"[{item.Result.CheckId}] {item.Finding.Description}";
            FindingsList.Items.Add(CreateFindingItem(severity, description));
        }
        
        // Add summary message for clean results
        if (!allFindings.Any())
        {
            var cleanRules = _currentScanSession.Results.Count(r => r.Status == "Success" && (r.Findings == null || !r.Findings.Any()));
            if (cleanRules > 0)
            {
                FindingsList.Items.Add(CreateFindingItem("Info", $"✓ {cleanRules} security checks passed with no issues found"));
            }
        }
        
        var totalIssues = allFindings.Count;
        var rulesExecuted = _currentScanSession.Results.Count(r => r.Status == "Success");
        var rulesFailed = _currentScanSession.Results.Count(r => r.Status == "Error" || r.Status == "Failed");
        
        StatusBarText.Text = $"Scan completed: {rulesExecuted} rules executed, {totalIssues} security issues found, {rulesFailed} rules failed";
        
        // Auto-upload results if authenticated
        if (_isAuthenticated && _currentScanSession.Results.Any())
        {
            StatusBarText.Text = "Uploading results to dashboard...";
            try
            {
                await UploadScanResultsAsync();
                OpenDashboardButton.IsEnabled = true;
                StatusBarText.Text = "Results uploaded - Click 'Open Dashboard' to view";
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to upload scan results");
                StatusBarText.Text = "Upload failed - Results saved locally";
            }
        }
        else if (!_isAuthenticated)
        {
            StatusBarText.Text = "Scan complete - Login to upload results to dashboard";
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
        try
        {
            var config = _configurationService?.Configuration;
            if (config == null) return;
            
            // Set scan checkboxes
            if (ScanADCheckbox != null)
                ScanADCheckbox.IsChecked = config.Scan.ScanActiveDirectory;
            if (ScanEntraCheckbox != null)
                ScanEntraCheckbox.IsChecked = config.Scan.ScanEntraId;
            if (ScanHybridCheckbox != null)
                ScanHybridCheckbox.IsChecked = config.Scan.ScanHybridIdentity;
            
            // Set backend selection
            if (BackendSelector != null && !string.IsNullOrEmpty(config.Backend.LastUsedBackend))
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
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to load configuration");
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
            // Update progress bar and percentage
            ScanProgressBar.Value = e.Progress;
            ProgressPercentageText.Text = $"{e.Progress:F0}%";
            
            // Update status and rule count
            ProgressStatusText.Text = $"Scanning ({e.CompletedRules}/{e.TotalRules})";
            
            // Calculate and display time information
            var elapsed = DateTime.Now - _scanStartTime;
            var estimatedTotal = elapsed.TotalSeconds * e.TotalRules / Math.Max(e.CompletedRules, 1);
            var remaining = TimeSpan.FromSeconds(Math.Max(0, estimatedTotal - elapsed.TotalSeconds));
            
            if (remaining.TotalMinutes > 1)
            {
                ProgressTimeText.Text = $"~{remaining.Minutes}m {remaining.Seconds}s remaining";
            }
            else
            {
                ProgressTimeText.Text = $"~{remaining.Seconds}s remaining";
            }
            
            // Show current rule details
            if (!string.IsNullOrEmpty(e.CurrentRule))
            {
                ProgressDetailsText.Text = $"Processing: {e.CurrentRule}";
            }
        });
    }

    private void OnRuleStarted(object? sender, RuleExecutionEventArgs e)
    {
        Dispatcher.Invoke(() =>
        {
            // Get rule info from manifest for better display
            var ruleInfo = _ruleManifest?.Rules.FirstOrDefault(r => r.Key == e.RuleName);
            if (ruleInfo.HasValue && ruleInfo.Value.Value != null)
            {
                var rule = ruleInfo.Value.Value;
                CurrentRuleText.Text = $"[{rule.Tier}] {rule.Name} - {rule.Category}";
                ProgressDetailsText.Text = $"Executing: {rule.Name}";
            }
            else
            {
                CurrentRuleText.Text = $"Executing: {e.RuleName}";
                ProgressDetailsText.Text = $"Executing: {e.RuleName}";
            }
        });
    }

    private void OnRuleCompleted(object? sender, RuleExecutionEventArgs e)
    {
        // Log completion for debugging
        _logger?.LogDebug("Rule {RuleName} completed", e.RuleName);
        
        Dispatcher.Invoke(() =>
        {
            // Update current rule display
            var ruleInfo = _ruleManifest?.Rules.FirstOrDefault(r => r.Key == e.RuleName);
            if (ruleInfo.HasValue && ruleInfo.Value.Value != null)
            {
                var rule = ruleInfo.Value.Value;
                CurrentRuleText.Text = $"[{rule.Tier}] {rule.Name} - Completed";
            }
        });
    }

    private void OnRuleError(object? sender, RuleExecutionEventArgs e)
    {
        _logger?.LogWarning("Rule {RuleName} failed: {Error}", e.RuleName, e.Error);
        
        Dispatcher.Invoke(() =>
        {
            // Show error in current rule display
            var ruleInfo = _ruleManifest?.Rules.FirstOrDefault(r => r.Key == e.RuleName);
            if (ruleInfo.HasValue && ruleInfo.Value.Value != null)
            {
                var rule = ruleInfo.Value.Value;
                CurrentRuleText.Text = $"[{rule.Tier}] {rule.Name} - Error (continuing...)";
            }
            else
            {
                CurrentRuleText.Text = $"{e.RuleName} - Error (continuing...)";
            }
        });
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

    private async Task CheckSystemRequirementsAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            _systemRequirements = await _systemRequirementsService.CheckRequirementsAsync(cancellationToken);
            await Dispatcher.InvokeAsync(() => UpdateSystemRequirementsUI());
        }
        catch (OperationCanceledException)
        {
            _logger?.LogDebug("System requirements check was cancelled");
            await Dispatcher.InvokeAsync(() =>
            {
                PowerShellStatusText.Text = "PowerShell: Available";
                DomainStatusText.Text = "Domain: Check timed out";
                AdminStatusText.Text = "Admin Rights: Check timed out";
            });
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to check system requirements");
            await Dispatcher.InvokeAsync(() =>
            {
                PowerShellStatusText.Text = "PowerShell: Error checking";
                DomainStatusText.Text = "Domain: Error checking";
                AdminStatusText.Text = "Admin Rights: Error checking";
            });
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

        // Update start scan button - warn but don't block for PowerShell
        if (!_systemRequirements.PowerShellAvailable)
        {
            // Don't disable the button, just show a warning tooltip
            StartScanButton.ToolTip = "Warning: PowerShell detection failed but scan may still work";
        }
        else
        {
            StartScanButton.ToolTip = _isAuthenticated ? null : "You can scan locally. Login to upload results to the cloud dashboard.";
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
            
            if (_entraIdAuthManager != null)
            {
                _entraIdAuthManager.AuthenticationStateChanged -= OnEntraIdAuthenticationStateChanged;
                _entraIdAuthManager.Dispose();
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