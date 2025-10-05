using DeviceId;

namespace Enigma.LicenseManager;

public static class LicenseUtils
{
    public static string GenerateDeviceId()
        => new DeviceIdBuilder().AddMachineName().AddOsVersion().ToString();
}