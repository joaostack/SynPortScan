using SynPortScan.Core;

namespace SynPortScan.Commands;

public class SynPortScanCommands
{
    private readonly string _ip;

    /// <summary>
    /// Initializes a new instance of the <see cref="SynPortScanCommands"/> class.
    /// </summary>
    /// <param name="ip">The target IP address to scan.</param>
    public SynPortScanCommands(string ip)
    {
        _ip = ip;
    }

    /// <summary>
    /// Scans a specific port on a target host using SYN scan.
    /// </summary>
    /// <param name="targetHost">The target host IP address.</param>
    /// <param name="port">The port number to scan.</param>
    public void Execute()
    {
        try
        {
            var device = DeviceHelper.SelectDevice();
            DeviceHelper.OpenDevice(device);
            var mac = PacketBuilder.GetMacFromIP(device, _ip);

            // add : on the mac address
            var macString = string.Join(":", mac.GetAddressBytes().Select(b => b.ToString("X2")));
            Console.WriteLine($"MAC address for {_ip}: {macString}");

            PacketBuilder.SendSynPacket(device, _ip, 80);

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