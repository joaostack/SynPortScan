namespace SynPortScan.Core;

using SharpPcap;
using PacketDotNet;

/// <summary>
/// PacketBuilder class for building and sending packets.
/// </summary>
public static class PacketBuilder
{
    // == Syn Scan Logic ==
    // 1. Send SYN packet to target host:port.
    // 2. Wait for response.
    // - If SYN-ACK is received, the port is open.
    // - If RST is received, the port is closed.
    // - If no response, the port is filtered by firewall.
    // 3. If the port is open, send an ACK packet to complete the handshake.

    public static string GetMacFromIP(CaptureDevice device, string targetIp)
    {
        var arpPacket = new ArpPacket()
        {
            Operation = ArpOperation.Request,
            DestinationHardwareAddress = PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"),
        };

        device.Send(arpPacket);
    }
}