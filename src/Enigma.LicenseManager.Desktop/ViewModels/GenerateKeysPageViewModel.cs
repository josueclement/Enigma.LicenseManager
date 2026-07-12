using System;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Threading.Tasks;
using Carbon.Avalonia.Desktop.Controls.InfoBar;
using Carbon.Avalonia.Desktop.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Enigma.LicenseManager.Desktop.Controls;
using Enigma.LicenseManager.Desktop.Models;
using Enigma.LicenseManager.Tools;
using Microsoft.Extensions.Options;

namespace Enigma.LicenseManager.Desktop.ViewModels;

/// <summary>
/// Generates an RSA or ML-DSA key pair and saves the public / private keys to PEM. All cryptographic
/// work is delegated to <see cref="IKeyGenerationService"/>; the CPU-bound generation runs on a
/// background thread behind a <see cref="ProgressOverlayCard"/>.
/// </summary>
public class GenerateKeysPageViewModel : ObservableObject
{
    private readonly IKeyGenerationService _keyGenerationService;
    private readonly IFileDialogService _fileDialogService;
    private readonly IInfoBarService _infoBarService;
    private readonly IOverlayService _overlayService;
    private readonly DefaultPathsOptions _defaultPaths;

    public GenerateKeysPageViewModel(
        IKeyGenerationService keyGenerationService,
        IFileDialogService fileDialogService,
        IInfoBarService infoBarService,
        IOverlayService overlayService,
        IOptions<DefaultPathsOptions> defaultPaths)
    {
        _keyGenerationService = keyGenerationService;
        _fileDialogService = fileDialogService;
        _infoBarService = infoBarService;
        _overlayService = overlayService;
        _defaultPaths = defaultPaths.Value;
        UpdateParameterOptions();

        BrowsePublicKeyPathCommand = new AsyncRelayCommand(BrowsePublicKeyPathAsync);
        BrowsePrivateKeyPathCommand = new AsyncRelayCommand(BrowsePrivateKeyPathAsync);
        GenerateKeysCommand = new AsyncRelayCommand(GenerateKeysAsync);
    }

    public AsyncRelayCommand BrowsePublicKeyPathCommand { get; }
    public AsyncRelayCommand BrowsePrivateKeyPathCommand { get; }
    public AsyncRelayCommand GenerateKeysCommand { get; }

    // RSA + ML-DSA only — ML-KEM is a KEM and irrelevant to signing licenses.
    public string[] AlgorithmOptions { get; } = ["RSA", "ML-DSA"];

    private int _selectedAlgorithmIndex;
    public int SelectedAlgorithmIndex
    {
        get => _selectedAlgorithmIndex;
        set
        {
            if (SetProperty(ref _selectedAlgorithmIndex, value))
                UpdateParameterOptions();
        }
    }

    public ObservableCollection<string> ParameterOptions { get; } = [];

    private int _selectedParameterIndex;
    public int SelectedParameterIndex
    {
        get => _selectedParameterIndex;
        set => SetProperty(ref _selectedParameterIndex, value);
    }

    private string? _password;
    public string? Password
    {
        get => _password;
        set
        {
            if (SetProperty(ref _password, value))
            {
                OnPropertyChanged(nameof(HasPasswordMismatch));
                OnPropertyChanged(nameof(PasswordMismatchMessage));
            }
        }
    }

    private string? _confirmPassword;
    public string? ConfirmPassword
    {
        get => _confirmPassword;
        set
        {
            if (SetProperty(ref _confirmPassword, value))
            {
                OnPropertyChanged(nameof(HasPasswordMismatch));
                OnPropertyChanged(nameof(PasswordMismatchMessage));
            }
        }
    }

    public bool HasPasswordMismatch =>
        !string.IsNullOrEmpty(Password) &&
        !string.IsNullOrEmpty(ConfirmPassword) &&
        Password != ConfirmPassword;

    public string? PasswordMismatchMessage =>
        HasPasswordMismatch ? "Passwords do not match" : null;

    private string? _publicKeyPath;
    public string? PublicKeyPath
    {
        get => _publicKeyPath;
        set
        {
            if (SetProperty(ref _publicKeyPath, value))
                PublicKeyPathHasError = false;
        }
    }

    private string? _privateKeyPath;
    public string? PrivateKeyPath
    {
        get => _privateKeyPath;
        set
        {
            if (SetProperty(ref _privateKeyPath, value))
                PrivateKeyPathHasError = false;
        }
    }

    // --- Validation error flags ---

    private bool _publicKeyPathHasError;
    public bool PublicKeyPathHasError
    {
        get => _publicKeyPathHasError;
        set => SetProperty(ref _publicKeyPathHasError, value);
    }

    private bool _privateKeyPathHasError;
    public bool PrivateKeyPathHasError
    {
        get => _privateKeyPathHasError;
        set => SetProperty(ref _privateKeyPathHasError, value);
    }

    private bool _isBusy;
    public bool IsBusy
    {
        get => _isBusy;
        set => SetProperty(ref _isBusy, value);
    }

    private void UpdateParameterOptions()
    {
        ParameterOptions.Clear();
        var options = SelectedAlgorithmIndex switch
        {
            0 => new[] { "2048", "3072", "4096", "8192" },
            // ML-DSA is fixed to level 87 — the only level the core library supports.
            1 => new[] { "ML-DSA-87" },
            _ => Array.Empty<string>()
        };
        foreach (var opt in options)
            ParameterOptions.Add(opt);
        // Pre-select 4096 (index 2) for RSA — the safer default; ML-DSA has a single option (index 0).
        SelectedParameterIndex = SelectedAlgorithmIndex == 0 ? 2 : 0;
    }

    private async Task BrowsePublicKeyPathAsync()
    {
        var path = await _fileDialogService.ShowSaveFileDialogAsync(
            "Save Public Key", _defaultPaths.Keys, "public.pem", ".pem", true, null);
        if (path is not null)
            PublicKeyPath = path;
    }

    private async Task BrowsePrivateKeyPathAsync()
    {
        var path = await _fileDialogService.ShowSaveFileDialogAsync(
            "Save Private Key", _defaultPaths.Keys, "private.pem", ".pem", true, null);
        if (path is not null)
            PrivateKeyPath = path;
    }

    private bool ValidateInputs()
    {
        PublicKeyPathHasError = string.IsNullOrWhiteSpace(PublicKeyPath);
        PrivateKeyPathHasError = string.IsNullOrWhiteSpace(PrivateKeyPath);
        return !(PublicKeyPathHasError || PrivateKeyPathHasError || HasPasswordMismatch);
    }

    private async Task GenerateKeysAsync()
    {
        if (IsBusy) return;
        if (!ValidateInputs()) return;

        IsBusy = true;
        await _overlayService.ShowAsync(new ProgressOverlayCard
        {
            Title = "Generating Keys",
            Message = "This may take a moment...",
            IsIndeterminate = true
        });
        try
        {
            var algorithm = SelectedAlgorithmIndex == 0 ? LicenseAlgorithm.Rsa : LicenseAlgorithm.MlDsa;
            // The enum value equals the RSA key size in bits; ignored for ML-DSA (fixed to level 87).
            var rsaKeySize = algorithm == LicenseAlgorithm.Rsa
                ? (RsaKeySize)int.Parse(ParameterOptions[SelectedParameterIndex], CultureInfo.InvariantCulture)
                : RsaKeySize.Rsa3072;

            var keyPair = await Task.Run(() => _keyGenerationService.GenerateKeyPair(algorithm, rsaKeySize));

            await using (var publicKeyStream = File.Create(PublicKeyPath!))
            await using (var privateKeyStream = File.Create(PrivateKeyPath!))
                await _keyGenerationService.SaveKeyPairAsync(keyPair, publicKeyStream, privateKeyStream, Password);

            await _overlayService.HideAsync();
            await _infoBarService.ShowAsync(bar =>
            {
                bar.Title = "Success";
                bar.Message = "Keys generated successfully.";
                bar.Severity = InfoBarSeverity.Success;
            });
        }
        catch (Exception ex)
        {
            await _overlayService.HideAsync();
            await _infoBarService.ShowAsync(bar =>
            {
                bar.Title = "Error";
                bar.Message = ex.Message;
                bar.Severity = InfoBarSeverity.Error;
            });
        }
        finally
        {
            IsBusy = false;
        }
    }
}
