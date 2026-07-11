using Avalonia;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NLog.Extensions.Logging;

namespace Enigma.LicenseManager.Desktop;

internal sealed class Program
{
    internal static IHost? AppHost { get; private set; }

    [STAThread]
    public static void Main(string[] args)
    {
        // On Linux, the DBus connection disposal races with the Avalonia
        // dispatcher shutdown, throwing a TaskCanceledException on the
        // thread pool. Swallow it so the process exits cleanly.
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            if (e.ExceptionObject is TaskCanceledException ex
                && ex.StackTrace?.Contains("Tmds.DBus") == true)
                Environment.Exit(0);
        };

        var configPath = ConfigurationSetup.GetConfigFilePath();
        ConfigurationSetup.EnsureConfigFileExists(configPath);

        AppHost = Host.CreateDefaultBuilder(args)
            .ConfigureAppConfiguration((_, config) =>
            {
                config.AddJsonFile(configPath, optional: true, reloadOnChange: false);
            })
            .ConfigureServices((context, services) =>
            {
                services.AddLogging(builder =>
                {
                    builder.ClearProviders();
                    builder.AddNLog();
                });
                services.AddAppConfiguration(context.Configuration);
                services.AddCarbonServices();
                services.AddLicenseTools();
                services.AddPagesAndViewModels();
            })
            .Build();

        AppHost.Start();

        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);

        // Clear the Avalonia SynchronizationContext so that StopAsync
        // continuations don't deadlock trying to post back to the
        // now-shutdown dispatcher (observed on Windows).
        SynchronizationContext.SetSynchronizationContext(null);
        AppHost.StopAsync().GetAwaiter().GetResult();
        AppHost.Dispose();
    }

    // Avalonia configuration, don't remove; also used by visual designer.
    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
#if DEBUG
            .WithDeveloperTools()
#endif
            .WithInterFont()
            .LogToTrace();
}
