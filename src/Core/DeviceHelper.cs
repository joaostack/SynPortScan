using System.Net;
using System.Net.NetworkInformation;
using SharpPcap;

namespace SynPortScan.Core;

/// <summary>
/// Provides methods to select a network device for packet capture.
/// </summary>
public static class DeviceHelper
{
    /// <summary>
    /// Selects a network device for packet capture.
    /// </summary>
    public static ILiveDevice SelectDevice()
    {
        var devices = CaptureDeviceList.Instance;

        if (devices.Count < 1)
        {
            throw new InvalidOperationException("No devices found! Please connect a network device");
        }

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(new string('-', 50));
        for (int i = 0; i < devices.Count; i++)
        {
            var device = devices[i];
            Console.WriteLine($"{i}: {device.Description} ({device.Name})");
        }
        Console.WriteLine(new string('-', 50));

        Console.Write("Select a device by number: ");
        int index = int.Parse(Console.ReadLine() ?? "0");
        Console.ResetColor();

        return devices[index];
    }

    /// <summary>
    /// Opens the specified network device in promiscuous mode.
    /// </summary>
    public static void OpenDevice(ILiveDevice device)
    {
        if (device == null)
        {
            throw new ArgumentNullException(nameof(device), "Device cannot be null.");
        }

        device.Open(DeviceModes.Promiscuous, 1000);
    }

    /// <summary>
    /// Helper for getting the gateway IP address (this is from my ArpPoison project)
    /// </summary>
    public static IPAddress GetGatewayIP()
    {
        return NetworkInterface
            .GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .SelectMany(n => n.GetIPProperties().GatewayAddresses)
            .Select(g => g.Address)
            .FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
    }
}