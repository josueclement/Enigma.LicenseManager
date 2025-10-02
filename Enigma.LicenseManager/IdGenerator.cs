using System;
using System.Reflection;
using DeviceId;

namespace Enigma.LicenseManager;

public static class IdGenerator
{
    public static string GenerateAppId()
    {
        var entryAssembly = Assembly.GetEntryAssembly() ??
                          throw new InvalidOperationException("Entry assembly not found.");
        var assemblyName = entryAssembly.GetName();
        return assemblyName.Name;
        
        // var appName = assemblyName.Name; // Just the name (e.g., "MyApp.Namespace")
        // var version = assemblyName.Version; // Version object (e.g., 1.0.0.0) 
    }

    public static string GenerateMachineId()
        => new DeviceIdBuilder().AddMachineName().AddOsVersion().ToString();
}