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
            var mac = PacketBuilder.GetMacFromIP(device, ip);
            var macString = string.Join(":", mac.GetAddressBytes().Select(b => b.ToString("X2")));
            Console.WriteLine($"MAC address for {ip}: {macString}");
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