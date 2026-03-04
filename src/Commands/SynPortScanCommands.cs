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
    private readonly string _ip;

    /// <summary>
    /// Initializes a new instance of the <see cref="SynPortScanCommands"/> class.
    /// </summary>
    public SynPortScanCommands(string ip)
    {
        _ip = ip;
    }

    /// <summary>
    /// Scans a specific port on a target host using SYN scan.
    /// </summary>
    public async Task ExecuteAsync(CancellationToken ct)
    {
        try
        {
            var device = DeviceHelper.SelectDevice();
            DeviceHelper.OpenDevice(device);
            var gatewayIP = DeviceHelper.GetGatewayIP();
            var gatewayMac = PhysicalAddress.Parse(await PacketBuilder.GetMacFromIP(device, gatewayIP.ToString(), ct));

            // add dots to the mac address
            var targetGatewayMacString = string.Join(":", gatewayMac.GetAddressBytes().Select(b => b.ToString("X2")));
            var ports = Enumerable.Range(0, 65535);

            Console.WriteLine($"[{DateTime.UtcNow}] - Scanning...");

            foreach (var port in ports)
                await PacketBuilder.SendSynPacket(device, _ip, port, gatewayMac);

            device.Close();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(ex.Message);
        }
        finally
        {
            Console.ResetColor();
        }
    }
}
