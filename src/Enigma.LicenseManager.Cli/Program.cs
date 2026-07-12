using System.CommandLine;
using System.Threading.Tasks;
using Enigma.LicenseManager.Tools;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Enigma.LicenseManager.Cli;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        // IHost + DI: register the shared Tools services, then resolve them for the command handlers.
        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddLicenseTools();
        using var host = builder.Build();

        var app = new CliApplication(
            host.Services.GetRequiredService<IKeyGenerationService>(),
            host.Services.GetRequiredService<ILicenseGenerationService>(),
            host.Services.GetRequiredService<ILicenseValidationService>());

        return await app.BuildRootCommand().Parse(args).InvokeAsync().ConfigureAwait(false);
    }
}
