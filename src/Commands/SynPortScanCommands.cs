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
    public void Execute()
    {
        try
        {
            var device = DeviceHelper.SelectDevice();
            DeviceHelper.OpenDevice(device);
            var gatewayMac = PacketBuilder.GetMacFromIP(device, _gateway);

            // add dots on the mac address
            var targetGatewayMacString = string.Join(":", gatewayMac.GetAddressBytes().Select(b => b.ToString("X2")));
            Console.WriteLine($"Gateway MAC address {gatewayMac} : {targetGatewayMacString}");

            PacketBuilder.SendSynPacket(device, _ip, int.Parse(_port), gatewayMac);

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