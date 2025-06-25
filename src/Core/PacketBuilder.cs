namespace SynPortScan.Core;

using SharpPcap;
using PacketDotNet;
using System.Net.NetworkInformation;
using System.Net;
using System.Net.Sockets;

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

    /// <summary>
    /// Gets the MAC address from the target IP address using ARP request.
    /// </summary>
    public static string GetMacFromIP(ILiveDevice device, string targetIp)
    {
        var localIp = ((SharpPcap.LibPcap.LibPcapLiveDevice)device).Addresses
            .FirstOrDefault(a =>
                a.Addr.ipAddress != null &&
                a.Addr.ipAddress.AddressFamily == AddressFamily.InterNetwork)
            ?.Addr.ipAddress;

        var localMac = device.MacAddress;

        var ethernetPacket = new EthernetPacket(
            PhysicalAddress.Parse("00-00-00-00-00-00"), // Source MAC (dummy)
            PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"), // Broadcast MAC
            EthernetType.Arp);

        var arpPacket = new ArpPacket(
            ArpOperation.Request,
            PhysicalAddress.Parse("00-00-00-00-00-00"),
            IPAddress.Parse(targetIp),
            localMac,
            localIp
        );

        ethernetPacket.PayloadPacket = arpPacket;

        string macRes = "";

        device.Open();
        device.OnPacketArrival += (sender, e) =>
        {
            var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
            var eth = packet.Extract<EthernetPacket>();
            var arp = packet.Extract<ArpPacket>();

            if (eth != null && arp != null &&
                arp.TargetProtocolAddress.ToString() == targetIp &&
                arp.Operation == ArpOperation.Response)
            {
                macRes = arp.SenderHardwareAddress.ToString();
                return;
            }
        };

        device.SendPacket(ethernetPacket);
        device.StartCapture();
        Thread.Sleep(2000);
        device.StopCapture();
        device.Close();

        return macRes ?? throw new InvalidOperationException("MAC address not found for the target IP.");
    }
}