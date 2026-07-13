using System.CommandLine.Help;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using SynPortScan.Core;

namespace SynPortScan.Commands;

/// <summary>
/// SynPortScanCommands class for executing SYN port scan commands.
/// </summary>
public class SynPortScanCommands
{
    private string IP { get; set; }
    private string InterfaceName { get; set; }
    private bool Verbose { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SynPortScanCommands"/> class.
    /// </summary>
    public SynPortScanCommands(string ip, string interfaceName, bool verbose)
    {
        this.IP = ip;
        this.Verbose = verbose;
        this.InterfaceName = interfaceName;
    }

    /// <summary>
    /// Scans a specific port on a target host using SYN scan.
    /// </summary>
    public async Task ExecuteAsync(CancellationToken ct)
    {
        var device = DeviceHelper.SelectDevice(InterfaceName);
        DeviceHelper.OpenDevice(device);
        var gatewayIp = DeviceHelper.GetGatewayIP();
        var gatewayMac = PhysicalAddress.Parse(await PacketBuilder.GetMacFromIP(device, gatewayIp.ToString(), ct));

        // add dots to the mac address
        var ports = Enumerable.Range(0, 65535);

        Console.WriteLine($"[{DateTime.UtcNow}] - Scanning...");

        await Parallel.ForEachAsync(ports,
            async (port, cancellationToken) =>
                await PacketBuilder.SendSynPacket(device, IP, port, Verbose, gatewayMac, cancellationToken));

        device.Close();
        Console.ResetColor();
    }
}