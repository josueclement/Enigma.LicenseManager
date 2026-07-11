using System;
using Enigma.LicenseManager;
using Enigma.LicenseManager.Tools;

// ReSharper disable once CheckNamespace — intentionally placed in the DI namespace for discoverability.
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Dependency-injection registration for the Enigma license-management tools.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the license tooling services — <see cref="IKeyGenerationService"/>,
    /// <see cref="ILicenseGenerationService"/> and <see cref="ILicenseValidationService"/> — together with
    /// the core <see cref="LicenseService"/>, all as singletons.
    /// </summary>
    /// <param name="services">The service collection to add the registrations to.</param>
    /// <returns>The same service collection, for chaining.</returns>
    public static IServiceCollection AddLicenseTools(this IServiceCollection services)
    {
        if (services is null) throw new ArgumentNullException(nameof(services));

        services.AddSingleton<LicenseService>();
        services.AddSingleton<IKeyGenerationService, KeyGenerationService>();
        services.AddSingleton<ILicenseGenerationService, LicenseGenerationService>();
        services.AddSingleton<ILicenseValidationService, LicenseValidationService>();
        return services;
    }
}
