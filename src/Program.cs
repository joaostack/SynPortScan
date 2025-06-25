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
    private static readonly string ASCII_ART = @"
 _   |~  _
[_]--'--[_]
|'|""`""|'|
| | /^\ | |
|_|_|I|_|_|
    SPS

BY github.com/joaostack";

    /// <summary>
    /// SynPortScan args.
    /// </summary>
    /// <param name="ip">Target IP</param>
    /// <param name="gateway">Target gateway</param>
    /// <param name="threads">Threads</param>
    static async Task Main(string ip, string gateway, int threads)
    {
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine(ASCII_ART);
        Console.ResetColor();

        if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(gateway))
        {
            Console.WriteLine("-?, -h, --help\tShow help and usage information");
            return;
        }

        if (threads <= 0)
        {
            threads = 2;
        }

        //Check if target is a hostname and convert to IP Address
        if (!IPAddress.TryParse(ip, out var host))
        {
            host = Dns.GetHostAddresses(ip).FirstOrDefault();
        }

        try
        {
            Console.WriteLine($"TARGET: {host}");

            var command = new SynPortScanCommands(host.ToString(), gateway, threads);
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