using Enigma.LicenseManager;
using Enigma.LicenseManager.Cli;
using Enigma.LicenseManager.Tools;
using Org.BouncyCastle.Crypto;
using System;
using System.CommandLine;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace UnitTests;

/// <summary>
/// Smoke tests for the <c>Enigma.LicenseManager.Cli</c> command surface. These verify the CLI's own
/// responsibilities — argument parsing maps onto the correct Tools call, and exit codes reflect the
/// outcome — using recording fakes so no crypto or file I/O runs. The heavy round-trip logic is already
/// covered by <see cref="ToolsTests"/>.
/// </summary>
public class CliTests
{
    private static Task<int> InvokeAsync(CliApplication app, params string[] args)
        => app.BuildRootCommand().Parse(args).InvokeAsync();

    [Fact]
    public async Task Keygen_ParsesArgumentsAndCallsKeyGenerationService()
    {
        var keyGen = new RecordingKeyGenerationService();
        var app = new CliApplication(keyGen, new ThrowingLicenseGenerationService(),
            new StubLicenseValidationService(valid: true));

        var exit = await InvokeAsync(app,
            "keygen", "-a", "rsa", "--rsa-size", "4096",
            "--public", "pub.pem", "--private", "priv.pem", "--password", "pw");

        Assert.Equal(0, exit);
        Assert.Equal(LicenseAlgorithm.Rsa, keyGen.Algorithm);
        Assert.Equal(RsaKeySize.Rsa4096, keyGen.RsaKeySize);
        Assert.Equal("pub.pem", keyGen.PublicKeyPath);
        Assert.Equal("priv.pem", keyGen.PrivateKeyPath);
        Assert.Equal("pw", keyGen.Password);
    }

    [Fact]
    public async Task Keygen_MlDsa_MapsAlgorithm()
    {
        var keyGen = new RecordingKeyGenerationService();
        var app = new CliApplication(keyGen, new ThrowingLicenseGenerationService(),
            new StubLicenseValidationService(valid: true));

        var exit = await InvokeAsync(app,
            "keygen", "--algorithm", "ml-dsa", "--public", "pub.pem", "--private", "priv.pem");

        Assert.Equal(0, exit);
        Assert.Equal(LicenseAlgorithm.MlDsa, keyGen.Algorithm);
        Assert.Null(keyGen.Password);
    }

    [Fact]
    public async Task Keygen_UnknownAlgorithm_IsRejectedWithoutCallingService()
    {
        var keyGen = new RecordingKeyGenerationService();
        var app = new CliApplication(keyGen, new ThrowingLicenseGenerationService(),
            new StubLicenseValidationService(valid: true));

        var exit = await InvokeAsync(app,
            "keygen", "-a", "bogus", "--public", "pub.pem", "--private", "priv.pem");

        Assert.NotEqual(0, exit);
        Assert.False(keyGen.WasCalled);
    }

    [Fact]
    public async Task LicenseGenerate_ParsesRequestAndCallsGenerationService()
    {
        var licenseGen = new RecordingLicenseGenerationService();
        var app = new CliApplication(new ThrowingKeyGenerationService(), licenseGen,
            new StubLicenseValidationService(valid: true));

        var exit = await InvokeAsync(app,
            "license", "generate", "--product-id", "MyApp 1.*", "--owner", "Alice",
            "--device-id", "dev-1", "--expires", "2027-01-31",
            "--algorithm", "ml-dsa", "--key", "priv.pem", "--out", "license.json");

        Assert.Equal(0, exit);
        Assert.NotNull(licenseGen.Request);
        Assert.Equal("MyApp 1.*", licenseGen.Request!.ProductId);
        Assert.Equal("Alice", licenseGen.Request.Owner);
        Assert.Equal("dev-1", licenseGen.Request.DeviceId);
        Assert.Equal(LicenseAlgorithm.MlDsa, licenseGen.Request.Algorithm);
        Assert.Equal(new DateTime(2027, 1, 31), licenseGen.Request.ExpirationDate);
        Assert.Equal("priv.pem", licenseGen.PrivateKeyPath);
        Assert.Equal("license.json", licenseGen.OutputPath);
    }

    [Fact]
    public async Task LicenseValidate_ValidLicense_ReturnsZero()
    {
        var app = new CliApplication(new ThrowingKeyGenerationService(),
            new ThrowingLicenseGenerationService(), new StubLicenseValidationService(valid: true));

        var exit = await InvokeAsync(app,
            "license", "validate", "--license", "license.json", "--public-key", "pub.pem");

        Assert.Equal(0, exit);
    }

    [Fact]
    public async Task LicenseValidate_InvalidLicense_ReturnsNonZero()
    {
        var app = new CliApplication(new ThrowingKeyGenerationService(),
            new ThrowingLicenseGenerationService(),
            new StubLicenseValidationService(valid: false, message: "signature is invalid"));

        var exit = await InvokeAsync(app,
            "license", "validate", "--license", "license.json", "--public-key", "pub.pem",
            "--product-id", "MyApp 1.2.3");

        Assert.NotEqual(0, exit);
    }

    // ---------- recording / stub fakes ----------

    private sealed class RecordingKeyGenerationService : IKeyGenerationService
    {
        public bool WasCalled { get; private set; }
        public LicenseAlgorithm Algorithm { get; private set; }
        public RsaKeySize RsaKeySize { get; private set; }
        public string? PublicKeyPath { get; private set; }
        public string? PrivateKeyPath { get; private set; }
        public string? Password { get; private set; }

        public Task GenerateAndSaveKeyPairAsync(LicenseAlgorithm algorithm, string publicKeyPath,
            string privateKeyPath, RsaKeySize rsaKeySize = RsaKeySize.Rsa3072, string? privateKeyPassword = null,
            CancellationToken cancellationToken = default)
        {
            WasCalled = true;
            Algorithm = algorithm;
            RsaKeySize = rsaKeySize;
            PublicKeyPath = publicKeyPath;
            PrivateKeyPath = privateKeyPath;
            Password = privateKeyPassword;
            return Task.CompletedTask;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair(LicenseAlgorithm algorithm,
            RsaKeySize rsaKeySize = RsaKeySize.Rsa3072) => throw new NotSupportedException();

        public Task SaveKeyPairAsync(AsymmetricCipherKeyPair keyPair, Stream publicKeyOutput,
            Stream privateKeyOutput, string? privateKeyPassword = null,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    private sealed class ThrowingKeyGenerationService : IKeyGenerationService
    {
        public Task GenerateAndSaveKeyPairAsync(LicenseAlgorithm algorithm, string publicKeyPath,
            string privateKeyPath, RsaKeySize rsaKeySize = RsaKeySize.Rsa3072, string? privateKeyPassword = null,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public AsymmetricCipherKeyPair GenerateKeyPair(LicenseAlgorithm algorithm,
            RsaKeySize rsaKeySize = RsaKeySize.Rsa3072) => throw new NotSupportedException();

        public Task SaveKeyPairAsync(AsymmetricCipherKeyPair keyPair, Stream publicKeyOutput,
            Stream privateKeyOutput, string? privateKeyPassword = null,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    private sealed class RecordingLicenseGenerationService : ILicenseGenerationService
    {
        public LicenseGenerationRequest? Request { get; private set; }
        public string? PrivateKeyPath { get; private set; }
        public string? Password { get; private set; }
        public string? OutputPath { get; private set; }

        public Task<License> CreateAndSaveLicenseAsync(LicenseGenerationRequest request, string privateKeyPath,
            string? privateKeyPassword, string outputPath, CancellationToken cancellationToken = default)
        {
            Request = request;
            PrivateKeyPath = privateKeyPath;
            Password = privateKeyPassword;
            OutputPath = outputPath;
            return Task.FromResult(new License { Id = "TEST", ProductId = request.ProductId });
        }

        public Task<License> CreateAndSaveLicenseAsync(LicenseGenerationRequest request,
            AsymmetricKeyParameter privateKey, Stream output, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<License> CreateAndSaveLicenseAsync(LicenseGenerationRequest request, Stream privateKeyInput,
            string? privateKeyPassword, Stream output, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private sealed class ThrowingLicenseGenerationService : ILicenseGenerationService
    {
        public Task<License> CreateAndSaveLicenseAsync(LicenseGenerationRequest request, string privateKeyPath,
            string? privateKeyPassword, string outputPath, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<License> CreateAndSaveLicenseAsync(LicenseGenerationRequest request,
            AsymmetricKeyParameter privateKey, Stream output, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<License> CreateAndSaveLicenseAsync(LicenseGenerationRequest request, Stream privateKeyInput,
            string? privateKeyPassword, Stream output, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private sealed class StubLicenseValidationService : ILicenseValidationService
    {
        private readonly bool _valid;
        private readonly string? _message;

        public StubLicenseValidationService(bool valid, string? message = null)
        {
            _valid = valid;
            _message = message;
        }

        public Task<LicenseValidationResult> ValidateAsync(string licensePath, string publicKeyPath,
            string? productId = null, string? deviceId = null, CancellationToken cancellationToken = default)
            => Task.FromResult(new LicenseValidationResult(_valid, _message, null));

        public Task<LicenseValidationResult> ValidateAsync(Stream licenseInput, Stream publicKeyInput,
            string? productId = null, string? deviceId = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }
}
