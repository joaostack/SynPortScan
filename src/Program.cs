namespace SynPortScan;

using System;
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
            PacketBuilder.GetMacFromIP(device, ip);
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