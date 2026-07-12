using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Styling;
using System;
using Avalonia.Markup.Xaml;
using Carbon.Avalonia.Desktop.Services;
using Enigma.LicenseManager.Desktop.Models;
using Enigma.LicenseManager.Desktop.ViewModels;
using Enigma.LicenseManager.Desktop.Views;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NLog.Extensions.Logging;

namespace Enigma.LicenseManager.Desktop;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        // When launched by the Avalonia Designer, Program.Main() is bypassed
        // so AppHost is null. Build a standalone provider as fallback.
        var services = Program.AppHost?.Services ?? BuildDesignerServices();

        // Initialize the theme from the saved config (this app does not force Dark).
        var options = services.GetRequiredService<IOptions<DefaultPathsOptions>>().Value;
        RequestedThemeVariant = ParseThemeVariant(options.Theme);

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var mainWindow = services.GetRequiredService<MainWindow>();
            var vm = services.GetRequiredService<MainWindowViewModel>();
            mainWindow.DataContext = vm;

            services.GetRequiredService<IContentDialogService>().RegisterHost(mainWindow.HostDialog);
            services.GetRequiredService<IOverlayService>().RegisterHost(mainWindow.HostOverlay);
            services.GetRequiredService<IInfoBarService>().RegisterHost(mainWindow.HostInfoBar);
            services.GetRequiredService<IFileDialogService>().SetStorageProvider(mainWindow.StorageProvider);
            services.GetRequiredService<IFolderDialogService>().SetStorageProvider(mainWindow.StorageProvider);

            desktop.MainWindow = mainWindow;
        }

        base.OnFrameworkInitializationCompleted();
    }

    private static ThemeVariant ParseThemeVariant(string? theme)
        => string.Equals(theme, "Light", StringComparison.OrdinalIgnoreCase)
            ? ThemeVariant.Light
            : ThemeVariant.Dark;

    private static IServiceProvider BuildDesignerServices()
    {
        var services = new ServiceCollection();
        services.AddLogging(builder =>
        {
            builder.ClearProviders();
            builder.AddNLog();
        });
        services.Configure<DefaultPathsOptions>(_ => { });
        services.AddCarbonServices();
        services.AddLicenseTools();
        services.AddPagesAndViewModels();
        return services.BuildServiceProvider();
    }
}
