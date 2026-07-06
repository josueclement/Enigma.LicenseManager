using Avalonia.Controls;
using Carbon.Avalonia.Desktop.Controls.ContentDialog;
using Enigma.LicenseManager.Desktop.ViewModels;

namespace Enigma.LicenseManager.Desktop.Views;

public partial class MainWindow : Window
{
    private bool _forceClose;

    public MainWindow()
    {
        InitializeComponent();
        Closing += OnClosing;
    }

    private async void OnClosing(object? sender, WindowClosingEventArgs e)
    {
        if (_forceClose) return;

        e.Cancel = true;

        if (DataContext is not MainWindowViewModel vm) return;

        var result = await vm.DialogService.ShowAsync(dialog =>
        {
            dialog.Title = "Quit application";
            dialog.Content = "Are you sure you want to leave?";
            dialog.PrimaryButtonText = "Leave";
            dialog.CloseButtonText = "Cancel";
        });

        if (result == DialogResult.Primary)
        {
            _forceClose = true;
            Close();
        }
    }
}
