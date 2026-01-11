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
    /// <param name="threads" >Threads</param>
    static async Task Main(string ip, int threads)
    {
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine(ASCII_ART);
        Console.ResetColor();

        if (string.IsNullOrEmpty(ip))
        {
            Console.WriteLine("-?, -h, --help\tShow help and usage information");
            return;
        }

        // set default threads if params is not specified
        if (threads <= 0)
        {
            threads = 2;
        }

        //Check if target is a hostname and convert to IP Address
        if (!IPAddress.TryParse(ip, out var host))
        {
            host = Dns.GetHostAddresses(ip).FirstOrDefault();
        }

        if (host == null)
        {
            Console.WriteLine("Missing host param!");
            return;
        }

        try
        {
            Console.WriteLine($"TARGET: {host}");

            var cts = new CancellationTokenSource();
            var command = new SynPortScanCommands(host.ToString(), threads);
            await command.ExecuteAsync(cts.Token);
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"ERROR: {ex.Message}");
        }
        finally
        {
            Console.ResetColor();
        }
    }
}
