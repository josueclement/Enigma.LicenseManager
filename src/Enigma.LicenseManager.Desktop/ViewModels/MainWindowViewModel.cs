using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Styling;
using Carbon.Avalonia.Desktop.Controls.Navigation;
using Carbon.Avalonia.Desktop.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Enigma.LicenseManager.Desktop.Views;
using Microsoft.Extensions.DependencyInjection;
using PhosphorIconsAvalonia;

namespace Enigma.LicenseManager.Desktop.ViewModels;

public class MainWindowViewModel : ObservableObject
{
    private readonly IServiceProvider _services;

    public MainWindowViewModel(
        IServiceProvider services,
        INavigationService navigation,
        IContentDialogService dialogService,
        IOverlayService overlayService,
        IInfoBarService infoBarService)
    {
        _services = services;
        Navigation = navigation;
        DialogService = dialogService;
        OverlayService = overlayService;
        InfoBarService = infoBarService;

        ThemeToggleIcon = IconService.CreateGeometry(Icon.circle_half, IconType.regular);
        ToggleThemeCommand = new RelayCommand(ToggleTheme);

        Navigation.PageFactory = navItem =>
        {
            var page = _services.GetRequiredService(navItem.PageType);
            if (page is not Control ctrl)
                throw new InvalidOperationException($"Page type {navItem.PageType} is not a Control");
            ctrl.DataContext = _services.GetRequiredService(navItem.PageViewModelType);
            return ctrl;
        };

        Navigation.Items.Add(new NavigationItem
        {
            Header = "Generate Keys",
            IconData = IconService.CreateGeometry(Icon.key, IconType.regular),
            PageType = typeof(GenerateKeysPageView),
            PageViewModelType = typeof(GenerateKeysPageViewModel)
        });
        Navigation.Items.Add(new NavigationItem
        {
            Header = "Generate Licenses",
            IconData = IconService.CreateGeometry(Icon.certificate, IconType.regular),
            PageType = typeof(GenerateLicensesPageView),
            PageViewModelType = typeof(GenerateLicensesPageViewModel)
        });
        Navigation.Items.Add(new NavigationItem
        {
            Header = "Validate Licenses",
            IconData = IconService.CreateGeometry(Icon.seal_check, IconType.regular),
            PageType = typeof(ValidateLicensesPageView),
            PageViewModelType = typeof(ValidateLicensesPageViewModel)
        });

        var firstPage = _services.GetRequiredService<GenerateKeysPageView>();
        firstPage.DataContext = _services.GetRequiredService<GenerateKeysPageViewModel>();
        Navigation.NavigateToAsync(firstPage).GetAwaiter().GetResult();
    }

    public INavigationService Navigation { get; }
    public IContentDialogService DialogService { get; }
    public IOverlayService OverlayService { get; }
    public IInfoBarService InfoBarService { get; }

    /// <summary>Icon shown on the theme-toggle control in the nav-rail footer.</summary>
    public Geometry ThemeToggleIcon { get; }

    /// <summary>Flips the application theme Light↔Dark at runtime and persists the choice.</summary>
    public IRelayCommand ToggleThemeCommand { get; }

    private void ToggleTheme()
    {
        if (Application.Current is not { } app)
            return;

        var newVariant = app.ActualThemeVariant == ThemeVariant.Dark
            ? ThemeVariant.Light
            : ThemeVariant.Dark;

        app.RequestedThemeVariant = newVariant;
        ConfigurationSetup.SaveTheme(newVariant == ThemeVariant.Light ? "Light" : "Dark");
    }
}
