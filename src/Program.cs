namespace SynPortScan;

using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using SynPortScan.Commands;
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
    /// <param name="port">Target port</param>
    /// <param name="gateway">Target gateway</param>
    static async Task Main(string ip, string port, string gateway)
    {
        Console.WriteLine("SynPortScan is a SYN port scanner.");

        if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(port) || string.IsNullOrEmpty(gateway))
        {
            Console.WriteLine("Usage: SynPortScan -h");
            return;
        }

        if (!IPAddress.TryParse(ip, out var host))
        {
            host = Dns.GetHostAddresses(ip).FirstOrDefault();
        }

        try
        {
            Console.WriteLine($"TARGET: {host}");

            var command = new SynPortScanCommands(host.ToString(), port, gateway);
            await command.Execute();
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