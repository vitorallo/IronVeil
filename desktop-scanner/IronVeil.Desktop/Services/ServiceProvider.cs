using IronVeil.Core.Services;
using IronVeil.PowerShell;
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
        
        // Register PowerShellExecutor as a factory to avoid initialization issues
        services.AddTransient<IPowerShellExecutor>(provider =>
        {
            var logger = provider.GetService<ILogger<PowerShellExecutor>>();
            try
            {
                return new PowerShellExecutor(logger);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to create PowerShellExecutor - using mock implementation");
                // Return a mock implementation for development/testing
                return new MockPowerShellExecutor(logger);
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