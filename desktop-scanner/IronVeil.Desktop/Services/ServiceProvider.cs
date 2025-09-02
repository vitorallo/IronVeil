using IronVeil.Core.Services;
using IronVeil.PowerShell;
using IronVeil.PowerShell.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IronVeil.Desktop.Services;

public static class ServiceProvider
{
    private static IServiceProvider? _serviceProvider;

    public static void Initialize()
    {
        var services = new ServiceCollection();
        
        // Logging
        services.AddLogging(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Information);
        });
        
        // Core services
        services.AddSingleton<IConfigurationService, ConfigurationService>();
        services.AddSingleton<ISystemRequirementsService, SystemRequirementsService>();
        services.AddHttpClient<IAuthenticationService, AuthenticationService>();
        services.AddHttpClient<IApiClient, ApiClient>();
        
        // Register ExternalPowerShellExecutor as singleton with error handling
        services.AddSingleton<IPowerShellExecutor>(provider =>
        {
            var logger = provider.GetService<ILogger<ExternalPowerShellExecutor>>();
            var ruleManifestService = new RuleManifestService(provider.GetService<ILogger<RuleManifestService>>());
            
            try
            {
                // Use external PowerShell process for full cmdlet compatibility
                return new ExternalPowerShellExecutor(logger, ruleManifestService);
            }
            catch (Exception ex)
            {
                logger?.LogCritical(ex, "Failed to initialize External PowerShell executor: {ErrorMessage}", ex.Message);
                
                // Show critical error dialog to user
                System.Windows.Application.Current?.Dispatcher.Invoke(() =>
                {
                    var errorMessage = $"CRITICAL: PowerShell Not Found\n\n" +
                                     $"{ex.Message}\n\n" +
                                     $"The application requires PowerShell to function.\n" +
                                     $"Please install one of the following:\n\n" +
                                     $"• PowerShell 7+ (Recommended)\n" +
                                     $"  Download from: https://aka.ms/powershell\n\n" +
                                     $"• Windows PowerShell 5.1 (Pre-installed on Windows 10/11)\n" +
                                     $"  Should be available at:\n" +
                                     $"  C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
                                     
                    System.Windows.MessageBox.Show(
                        errorMessage,
                        "PowerShell Not Found",
                        System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Error);
                });
                
                throw; // Re-throw to prevent the application from starting without PowerShell
            }
        });
        
        _serviceProvider = services.BuildServiceProvider();
    }

    public static T GetRequiredService<T>() where T : notnull
    {
        if (_serviceProvider == null)
            throw new InvalidOperationException("ServiceProvider not initialized. Call Initialize() first.");
            
        return _serviceProvider.GetRequiredService<T>();
    }

    public static T? GetService<T>()
    {
        if (_serviceProvider == null)
            return default;
            
        return _serviceProvider.GetService<T>();
    }

    public static void Dispose()
    {
        if (_serviceProvider is IDisposable disposable)
        {
            disposable.Dispose();
        }
        _serviceProvider = null;
    }
}