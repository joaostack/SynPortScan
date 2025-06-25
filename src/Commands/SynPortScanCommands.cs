using System.Threading.Tasks;
using SynPortScan.Core;

namespace SynPortScan.Commands;

/// <summary>
/// SynPortScanCommands class for executing SYN port scan commands.
/// </summary>
public class SynPortScanCommands
{
    private readonly string _ip;
    private readonly string _port;
    private readonly string _gateway;

    /// <summary>
    /// Initializes a new instance of the <see cref="SynPortScanCommands"/> class.
    /// </summary>
    public SynPortScanCommands(string ip, string port, string gateway)
    {
        _ip = ip;
        _port = port;
        _gateway = gateway;
    }

    /// <summary>
    /// Scans a specific port on a target host using SYN scan.
    /// </summary>
    public async Task Execute()
    {
        try
        {
            CancellationToken ct = new CancellationToken();

            var device = DeviceHelper.SelectDevice();
            DeviceHelper.OpenDevice(device);
            var gatewayMac = await PacketBuilder.GetMacFromIP(device, _gateway, ct);

            // add dots on the mac address
            var targetGatewayMacString = string.Join(":", gatewayMac.GetAddressBytes().Select(b => b.ToString("X2")));

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[+] Gateway MAC address {_gateway} : {targetGatewayMacString}");

            // SAMPLE PORTS, FOR TESTING ONLY...
            var ports = new List<int>() { 80, 443, 23, 21, 22, 8080, 8000 };

            //await PacketBuilder.SendSynPacket(device, _ip, int.Parse(_port), gatewayMac, ct);

            foreach (var port in ports)
            {
                await PacketBuilder.SendSynPacket(device, _ip, port, gatewayMac, ct);
            }

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