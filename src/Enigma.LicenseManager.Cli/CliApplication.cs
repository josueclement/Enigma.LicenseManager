using System;
using System.CommandLine;
using System.Threading;
using System.Threading.Tasks;
using Enigma.LicenseManager.Tools;

namespace Enigma.LicenseManager.Cli;

/// <summary>
/// Builds the System.CommandLine command tree and maps parsed arguments onto the shared
/// <see cref="Enigma.LicenseManager.Tools"/> services. The class is intentionally thin: it does argument
/// parsing, output, and exit-code mapping only — all cryptographic and orchestration logic lives in the
/// Tools layer (already covered by its unit tests).
/// </summary>
public sealed class CliApplication
{
    private const string RsaAlgorithm = "rsa";
    private const string MlDsaAlgorithm = "ml-dsa";

    private readonly IKeyGenerationService _keyGeneration;
    private readonly ILicenseGenerationService _licenseGeneration;
    private readonly ILicenseValidationService _licenseValidation;

    /// <summary>
    /// Initializes a new instance backed by the given Tools services (registered via <c>AddLicenseTools</c>).
    /// </summary>
    public CliApplication(IKeyGenerationService keyGeneration, ILicenseGenerationService licenseGeneration,
        ILicenseValidationService licenseValidation)
    {
        _keyGeneration = keyGeneration ?? throw new ArgumentNullException(nameof(keyGeneration));
        _licenseGeneration = licenseGeneration ?? throw new ArgumentNullException(nameof(licenseGeneration));
        _licenseValidation = licenseValidation ?? throw new ArgumentNullException(nameof(licenseValidation));
    }

    /// <summary>
    /// Builds the root command with its <c>keygen</c> and <c>license</c> (generate / validate) subcommands.
    /// System.CommandLine supplies <c>--help</c> and <c>--version</c> automatically.
    /// </summary>
    public RootCommand BuildRootCommand()
    {
        var root = new RootCommand(
            "Enigma license manager — generate keys, generate and validate licenses.");
        root.Subcommands.Add(BuildKeygenCommand());
        root.Subcommands.Add(BuildLicenseCommand());
        return root;
    }

    private Command BuildKeygenCommand()
    {
        var algorithmOption = new Option<string>("--algorithm", "-a")
        {
            Description = "Signature algorithm: 'rsa' or 'ml-dsa' (ML-DSA is level 87).",
            Required = true
        };
        algorithmOption.AcceptOnlyFromAmong(RsaAlgorithm, MlDsaAlgorithm);

        var rsaSizeOption = new Option<int>("--rsa-size")
        {
            Description = "RSA key size in bits (RSA only; ignored for ml-dsa). One of 2048, 3072, 4096, 8192.",
            DefaultValueFactory = _ => (int)RsaKeySize.Rsa3072
        };
        rsaSizeOption.AcceptOnlyFromAmong("2048", "3072", "4096", "8192");

        var publicOption = new Option<string>("--public")
        {
            Description = "Output path for the public key (PEM).",
            Required = true
        };
        var privateOption = new Option<string>("--private")
        {
            Description = "Output path for the private key (PEM).",
            Required = true
        };
        var passwordOption = new Option<string?>("--password")
        {
            Description = "Optional password; when set, the private key is encrypted (AES-256-CBC)."
        };

        var command = new Command("keygen", "Generate an RSA or ML-DSA key pair and save it as PEM.");
        command.Options.Add(algorithmOption);
        command.Options.Add(rsaSizeOption);
        command.Options.Add(publicOption);
        command.Options.Add(privateOption);
        command.Options.Add(passwordOption);

        command.SetAction((parseResult, cancellationToken) => RunKeygenAsync(
            ParseAlgorithm(parseResult.GetValue(algorithmOption)!),
            (RsaKeySize)parseResult.GetValue(rsaSizeOption),
            parseResult.GetValue(publicOption)!,
            parseResult.GetValue(privateOption)!,
            parseResult.GetValue(passwordOption),
            cancellationToken));

        return command;
    }

    private Command BuildLicenseCommand()
    {
        var command = new Command("license", "Generate and validate licenses.");
        command.Subcommands.Add(BuildLicenseGenerateCommand());
        command.Subcommands.Add(BuildLicenseValidateCommand());
        return command;
    }

    private Command BuildLicenseGenerateCommand()
    {
        var productIdOption = new Option<string>("--product-id")
        {
            Description = "Product identifier the license applies to (supports wildcards, e.g. 'MyApp 1.*').",
            Required = true
        };
        var ownerOption = new Option<string?>("--owner") { Description = "Optional license owner." };
        var deviceIdOption = new Option<string?>("--device-id")
        {
            Description = "Optional device identifier to bind the license to a specific device."
        };
        var expiresOption = new Option<DateTime?>("--expires")
        {
            Description = "Optional expiration date (e.g. 2027-01-31). When omitted, the license never expires."
        };
        var algorithmOption = new Option<string>("--algorithm", "-a")
        {
            Description = "Signature algorithm: 'rsa' or 'ml-dsa' (must match the private key).",
            Required = true
        };
        algorithmOption.AcceptOnlyFromAmong(RsaAlgorithm, MlDsaAlgorithm);
        var keyOption = new Option<string>("--key")
        {
            Description = "Path to the private key (PEM) to sign the license with.",
            Required = true
        };
        var passwordOption = new Option<string?>("--password")
        {
            Description = "Optional password for an encrypted private key."
        };
        var outOption = new Option<string>("--out")
        {
            Description = "Output path for the signed license (JSON).",
            Required = true
        };

        var command = new Command("generate", "Build, sign and save a license.");
        command.Options.Add(productIdOption);
        command.Options.Add(ownerOption);
        command.Options.Add(deviceIdOption);
        command.Options.Add(expiresOption);
        command.Options.Add(algorithmOption);
        command.Options.Add(keyOption);
        command.Options.Add(passwordOption);
        command.Options.Add(outOption);

        command.SetAction((parseResult, cancellationToken) =>
        {
            var request = new LicenseGenerationRequest
            {
                ProductId = parseResult.GetValue(productIdOption)!,
                Algorithm = ParseAlgorithm(parseResult.GetValue(algorithmOption)!),
                Owner = parseResult.GetValue(ownerOption),
                DeviceId = parseResult.GetValue(deviceIdOption),
                ExpirationDate = parseResult.GetValue(expiresOption)
            };
            return RunLicenseGenerateAsync(
                request,
                parseResult.GetValue(keyOption)!,
                parseResult.GetValue(passwordOption),
                parseResult.GetValue(outOption)!,
                cancellationToken);
        });

        return command;
    }

    private Command BuildLicenseValidateCommand()
    {
        var licenseOption = new Option<string>("--license")
        {
            Description = "Path to the license (JSON) to validate.",
            Required = true
        };
        var publicKeyOption = new Option<string>("--public-key")
        {
            Description = "Path to the public key (PEM) to verify the signature with.",
            Required = true
        };
        var productIdOption = new Option<string?>("--product-id")
        {
            Description = "Product identifier to validate against. When omitted, the license's own product id is used."
        };
        var deviceIdOption = new Option<string?>("--device-id")
        {
            Description = "Optional device identifier to validate against."
        };

        var command = new Command("validate",
            "Validate a license against a public key. Exit code 0 = valid, non-zero = invalid.");
        command.Options.Add(licenseOption);
        command.Options.Add(publicKeyOption);
        command.Options.Add(productIdOption);
        command.Options.Add(deviceIdOption);

        command.SetAction((parseResult, cancellationToken) => RunLicenseValidateAsync(
            parseResult.GetValue(licenseOption)!,
            parseResult.GetValue(publicKeyOption)!,
            parseResult.GetValue(productIdOption),
            parseResult.GetValue(deviceIdOption),
            cancellationToken));

        return command;
    }

    private async Task<int> RunKeygenAsync(LicenseAlgorithm algorithm, RsaKeySize rsaKeySize,
        string publicKeyPath, string privateKeyPath, string? password, CancellationToken cancellationToken)
    {
        try
        {
            await _keyGeneration.GenerateAndSaveKeyPairAsync(algorithm, publicKeyPath, privateKeyPath,
                rsaKeySize, password, cancellationToken).ConfigureAwait(false);
            Console.WriteLine("Key pair generated:");
            Console.WriteLine($"  public:  {publicKeyPath}");
            Console.WriteLine($"  private: {privateKeyPath}");
            return ExitCodes.Success;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return ExitCodes.Error;
        }
    }

    private async Task<int> RunLicenseGenerateAsync(LicenseGenerationRequest request, string privateKeyPath,
        string? password, string outputPath, CancellationToken cancellationToken)
    {
        try
        {
            var license = await _licenseGeneration.CreateAndSaveLicenseAsync(request, privateKeyPath, password,
                outputPath, cancellationToken).ConfigureAwait(false);
            Console.WriteLine($"License generated: {license.Id}");
            Console.WriteLine($"  product: {license.ProductId}");
            Console.WriteLine($"  output:  {outputPath}");
            return ExitCodes.Success;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return ExitCodes.Error;
        }
    }

    private async Task<int> RunLicenseValidateAsync(string licensePath, string publicKeyPath,
        string? productId, string? deviceId, CancellationToken cancellationToken)
    {
        try
        {
            var result = await _licenseValidation.ValidateAsync(licensePath, publicKeyPath, productId, deviceId,
                cancellationToken).ConfigureAwait(false);
            if (result.IsValid)
            {
                Console.WriteLine("License is VALID.");
                return ExitCodes.Success;
            }

            Console.WriteLine($"License is INVALID: {result.Message}");
            return ExitCodes.LicenseInvalid;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return ExitCodes.Error;
        }
    }

    /// <summary>
    /// Maps the validated <c>--algorithm</c> token onto a <see cref="LicenseAlgorithm"/>. The option is
    /// restricted to the two accepted values at parse time, so the default arm is defensive only.
    /// </summary>
    private static LicenseAlgorithm ParseAlgorithm(string value) => value switch
    {
        RsaAlgorithm => LicenseAlgorithm.Rsa,
        MlDsaAlgorithm => LicenseAlgorithm.MlDsa,
        _ => throw new ArgumentException($"Unsupported algorithm '{value}'.", nameof(value))
    };
}
