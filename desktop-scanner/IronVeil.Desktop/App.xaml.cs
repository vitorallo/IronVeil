using System.Configuration;
using System.Data;
using System.Windows;
using System.Windows.Threading;
using IronVeil.Desktop.Services;

namespace IronVeil.Desktop;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        Console.WriteLine("App.OnStartup called");
        
        // Handle unhandled exceptions to prevent app crashes
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        
        base.OnStartup(e);
        
        try
        {
            // Initialize dependency injection
            Console.WriteLine("Initializing ServiceProvider...");
            ServiceProvider.Initialize();
            Console.WriteLine("ServiceProvider initialized");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ERROR initializing ServiceProvider: {ex.Message}");
            MessageBox.Show($"Failed to initialize application services: {ex.Message}", "Startup Error", 
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    
    private void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        var exception = e.ExceptionObject as Exception;
        Console.WriteLine($"UNHANDLED EXCEPTION: {exception?.Message}");
        MessageBox.Show($"An unexpected error occurred: {exception?.Message}", "Error", 
            MessageBoxButton.OK, MessageBoxImage.Error);
    }
    
    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Console.WriteLine($"DISPATCHER EXCEPTION: {e.Exception.Message}");
        // Log the error but don't show message box for every error
        // Only show for critical errors
        if (e.Exception is InvalidOperationException || 
            e.Exception is NullReferenceException)
        {
            // These are typically initialization issues - just log them
            Console.WriteLine($"Handled initialization exception: {e.Exception.GetType().Name}");
        }
        else
        {
            // Show message for unexpected errors
            MessageBox.Show($"An unexpected error occurred: {e.Exception.Message}", "Error", 
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        e.Handled = true; // Prevent app from crashing
    }

    protected override void OnExit(ExitEventArgs e)
    {
        // Clean up services
        ServiceProvider.Dispose();
        
        base.OnExit(e);
    }
}

