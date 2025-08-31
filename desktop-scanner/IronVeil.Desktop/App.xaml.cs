using System.Configuration;
using System.Data;
using System.Windows;
using IronVeil.Desktop.Services;

namespace IronVeil.Desktop;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        
        // Initialize dependency injection
        ServiceProvider.Initialize();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        // Clean up services
        ServiceProvider.Dispose();
        
        base.OnExit(e);
    }
}

