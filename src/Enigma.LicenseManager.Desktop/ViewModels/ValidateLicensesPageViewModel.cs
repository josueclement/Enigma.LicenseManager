using System;
using System.Linq;
using System.Threading.Tasks;
using Carbon.Avalonia.Desktop.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Enigma.LicenseManager.Desktop.Models;
using Enigma.LicenseManager.Tools;
using Microsoft.Extensions.Options;

namespace Enigma.LicenseManager.Desktop.ViewModels;

/// <summary>
/// Validates a license against a public key, delegating to <see cref="ILicenseValidationService"/>.
/// The outcome is shown as inline result text; malformed input is reported as an invalid result rather
/// than throwing.
/// </summary>
public class ValidateLicensesPageViewModel : ObservableObject
{
    private readonly ILicenseValidationService _licenseValidationService;
    private readonly IFileDialogService _fileDialogService;
    private readonly DefaultPathsOptions _defaultPaths;

    public ValidateLicensesPageViewModel(
        ILicenseValidationService licenseValidationService,
        IFileDialogService fileDialogService,
        IOptions<DefaultPathsOptions> defaultPaths)
    {
        _licenseValidationService = licenseValidationService;
        _fileDialogService = fileDialogService;
        _defaultPaths = defaultPaths.Value;

        BrowseValidateLicenseCommand = new AsyncRelayCommand(BrowseValidateLicenseAsync);
        BrowseValidatePublicKeyCommand = new AsyncRelayCommand(BrowseValidatePublicKeyAsync);
        ValidateLicenseCommand = new AsyncRelayCommand(ValidateLicenseAsync);
    }

    public AsyncRelayCommand BrowseValidateLicenseCommand { get; }
    public AsyncRelayCommand BrowseValidatePublicKeyCommand { get; }
    public AsyncRelayCommand ValidateLicenseCommand { get; }

    private string? _validateLicensePath;
    public string? ValidateLicensePath
    {
        get => _validateLicensePath;
        set
        {
            if (SetProperty(ref _validateLicensePath, value))
                LicensePathHasError = false;
        }
    }

    private string? _validatePublicKeyPath;
    public string? ValidatePublicKeyPath
    {
        get => _validatePublicKeyPath;
        set
        {
            if (SetProperty(ref _validatePublicKeyPath, value))
                PublicKeyPathHasError = false;
        }
    }

    // --- Validation error flags ---

    private bool _licensePathHasError;
    public bool LicensePathHasError
    {
        get => _licensePathHasError;
        set => SetProperty(ref _licensePathHasError, value);
    }

    private bool _publicKeyPathHasError;
    public bool PublicKeyPathHasError
    {
        get => _publicKeyPathHasError;
        set => SetProperty(ref _publicKeyPathHasError, value);
    }

    private string? _validateProductId;
    public string? ValidateProductId
    {
        get => _validateProductId;
        set => SetProperty(ref _validateProductId, value);
    }

    private string? _validateDeviceId;
    public string? ValidateDeviceId
    {
        get => _validateDeviceId;
        set => SetProperty(ref _validateDeviceId, value);
    }

    private string? _validationResult;
    public string? ValidationResult
    {
        get => _validationResult;
        set
        {
            if (SetProperty(ref _validationResult, value))
                OnPropertyChanged(nameof(HasValidationResult));
        }
    }

    private bool? _isValidationSuccess;
    public bool? IsValidationSuccess
    {
        get => _isValidationSuccess;
        set => SetProperty(ref _isValidationSuccess, value);
    }

    public bool HasValidationResult => ValidationResult is not null;

    private bool _isBusy;
    public bool IsBusy
    {
        get => _isBusy;
        set => SetProperty(ref _isBusy, value);
    }

    private async Task BrowseValidateLicenseAsync()
    {
        var paths = await _fileDialogService.ShowOpenFileDialogAsync(
            "Select License File", false, _defaultPaths.Licenses, "", null);
        if (paths.Any())
            ValidateLicensePath = paths.First();
    }

    private async Task BrowseValidatePublicKeyAsync()
    {
        var paths = await _fileDialogService.ShowOpenFileDialogAsync(
            "Select Public Key", false, _defaultPaths.Keys, "", null);
        if (paths.Any())
            ValidatePublicKeyPath = paths.First();
    }

    private bool ValidateInputs()
    {
        LicensePathHasError = string.IsNullOrWhiteSpace(ValidateLicensePath);
        PublicKeyPathHasError = string.IsNullOrWhiteSpace(ValidatePublicKeyPath);
        return !(LicensePathHasError || PublicKeyPathHasError);
    }

    private async Task ValidateLicenseAsync()
    {
        if (IsBusy) return;
        if (!ValidateInputs()) return;

        IsBusy = true;
        try
        {
            // A blank product / device id means "don't constrain on it"; the service validates the
            // license against its own product id when none is supplied.
            var result = await _licenseValidationService.ValidateAsync(
                ValidateLicensePath!, ValidatePublicKeyPath!,
                string.IsNullOrWhiteSpace(ValidateProductId) ? null : ValidateProductId,
                string.IsNullOrWhiteSpace(ValidateDeviceId) ? null : ValidateDeviceId);

            IsValidationSuccess = result.IsValid;
            ValidationResult = result.IsValid
                ? "License is valid."
                : $"License is invalid: {result.Message}";
        }
        catch (Exception ex)
        {
            IsValidationSuccess = false;
            ValidationResult = $"Error: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
