using System.Threading.Tasks;
using SynPortScan.Core;

namespace SynPortScan.Commands;

/// <summary>
/// SynPortScanCommands class for executing SYN port scan commands.
/// </summary>
public class SynPortScanCommands
{
    private readonly string _ip;
    private readonly string _gateway;

    /// <summary>
    /// Initializes a new instance of the <see cref="SynPortScanCommands"/> class.
    /// </summary>
    public SynPortScanCommands(string ip, string gateway)
    {
        _ip = ip;
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
            var ports = new List<int>()
            {
                20,
                21,
                22,
                23,
                25,
                53,
                67,
                68,
                69,
                80,
                110,
                123,
                143,
                161,
                194,
                443,
                445,
                465,
                587,
                993,
                995,
                1433,
                1521,
                3306,
                3389,
                5432,
                5900,
                6379,
                8080
            };

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