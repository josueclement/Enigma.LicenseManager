using DeviceId;
using System.Reflection;

namespace Enigma.LicenseManager;

/// <summary>
/// Utility class providing helper methods for license management.
/// </summary>
public static class LicenseUtils
{
    /// <summary>
    /// Generates a unique device identifier based on the machine name and operating system version.
    /// </summary>
    /// <returns>A string representing the unique device identifier.</returns>
    public static string GenerateDeviceId()
        => new DeviceIdBuilder().AddMachineName().AddOsVersion().ToString();
    
    /// <summary>
    /// Gets the name of the currently executing application.
    /// </summary>
    /// <returns>The application name, or null if the entry assembly cannot be determined.</returns>
    public static string? GetExecutingAppName()
        => Assembly.GetEntryAssembly()?.GetName().Name;
    
    /// <summary>
    /// Gets the version of the currently executing application.
    /// </summary>
    /// <returns>The application version as a string, or null if the entry assembly or version cannot be determined.</returns>
    public static string? GetExecutingAppVersion()
        => Assembly.GetEntryAssembly()?.GetName().Version?.ToString();
}