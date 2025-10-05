using DeviceId;

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
}