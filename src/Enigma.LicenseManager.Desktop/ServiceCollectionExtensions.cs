using Carbon.Avalonia.Desktop.Services;
using Enigma.LicenseManager.Desktop.Models;
using Enigma.LicenseManager.Desktop.ViewModels;
using Enigma.LicenseManager.Desktop.Views;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Enigma.LicenseManager.Desktop;

public static class ServiceCollectionExtensions
{
    extension(IServiceCollection services)
    {
        public void AddAppConfiguration(IConfiguration configuration)
        {
            _ = services.Configure<DefaultPathsOptions>(
                configuration.GetSection(DefaultPathsOptions.SectionName));
        }

        public void AddCarbonServices()
        {
            _ = services.AddSingleton<IFileDialogService, FileDialogService>();
            _ = services.AddSingleton<IFolderDialogService, FolderDialogService>();
            _ = services.AddSingleton<INavigationService, NavigationService>();
            _ = services.AddSingleton<IContentDialogService, ContentDialogService>();
            _ = services.AddSingleton<IInfoBarService, InfoBarService>();
            _ = services.AddSingleton<IOverlayService, OverlayService>();
        }

        public void AddPagesAndViewModels()
        {
            _ = services.AddSingleton<MainWindow>();
            _ = services.AddTransient<GenerateKeysPageView>();
            _ = services.AddTransient<GenerateLicensesPageView>();
            _ = services.AddTransient<ValidateLicensesPageView>();

            _ = services.AddSingleton<MainWindowViewModel>();
            _ = services.AddSingleton<GenerateKeysPageViewModel>();
            _ = services.AddSingleton<GenerateLicensesPageViewModel>();
            _ = services.AddSingleton<ValidateLicensesPageViewModel>();
        }
    }
}
