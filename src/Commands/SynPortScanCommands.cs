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
    private string Ip { get; set; }
    private string InterfaceName { get; set; }
    private bool Verbose { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SynPortScanCommands"/> class.
    /// </summary>
    public SynPortScanCommands(string ip, string interfaceName, bool verbose)
    {
        this.Ip = ip;
        this.Verbose = verbose;
        this.InterfaceName = interfaceName;
    }

    /// <summary>
    /// Scans a specific port on a target host using SYN scan.
    /// </summary>
    public async Task ExecuteAsync()
    {
        var device = DeviceHelper.SelectDevice(InterfaceName);
        DeviceHelper.OpenDevice(device);
        var gatewayIp = DeviceHelper.GetGatewayIP();
        var gatewayMac = PhysicalAddress.Parse(await PacketBuilder.GetMacFromIP(device, gatewayIp.ToString()));

        device.Filter = $"tcp and host {Ip}";
        device.OnPacketArrival += PacketBuilder.PacketArrival;
        device.StartCapture();

        Console.WriteLine($"[{DateTime.UtcNow}] - Scanning...");

        var ct = new CancellationTokenSource();

        var ports = Enumerable.Range(1, 65535);
        var tasks = ports
            .Select(port => PacketBuilder.SendSynPacket(
                device,
                Ip,
                port,
                Verbose,
                gatewayMac,
                ct.Token));

        await Task.WhenAll(tasks);
        
        device.OnPacketArrival -= PacketBuilder.PacketArrival;
        device.StopCapture();
        device.Close();
        Console.ResetColor();
    }
}