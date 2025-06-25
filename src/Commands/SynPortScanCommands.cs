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
            PacketBuilder.SendSynPacket(device, _ip, 80, mac);

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