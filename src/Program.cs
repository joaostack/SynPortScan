namespace SynPortScan;

using System;
using System.Net.NetworkInformation;
using SynPortScan.Core;

/// <summary>
/// SynPortScan application.
/// </summary>
public class Program
{
    /// <summary>
    /// SynPortScan args.
    /// </summary>
    /// <param name="ip">Target IP</param>
    static void Main(string ip)
    {
        Console.WriteLine("SynPortScan is a SYN port scanner.");

        if (string.IsNullOrEmpty(ip))
        {
            Console.WriteLine("Usage: SynPortScan -h");
            return;
        }

        try
        {
            var device = DeviceHelper.SelectDevice();
            DeviceHelper.OpenDevice(device);
            var mac = PacketBuilder.GetMacFromIP(device, ip);

            // add : on the mac address
            var macString = string.Join(":", mac.GetAddressBytes().Select(b => b.ToString("X2")));
            Console.WriteLine($"MAC address for {ip}: {macString}");

            PacketBuilder.SendSynPacket(device, ip, 80);

            device.Close();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error: {ex.Message}");
        }
        finally
        {
            Console.ResetColor();
        }
    }
}