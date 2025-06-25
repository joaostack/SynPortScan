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
    public static PhysicalAddress GetMacFromIP(ILiveDevice device, string targetIp)
    {
        var localIp = ((SharpPcap.LibPcap.LibPcapLiveDevice)device).Addresses
            .FirstOrDefault(a =>
                a.Addr.ipAddress != null &&
                a.Addr.ipAddress.AddressFamily == AddressFamily.InterNetwork)
            ?.Addr.ipAddress;

        var localMac = device.MacAddress;

        var ethernetPacket = new EthernetPacket(
            localMac,
            PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"), // Broadcast MAC
            EthernetType.Arp);

        var arpPacket = new ArpPacket(
            ArpOperation.Request,
            localMac,
            IPAddress.Parse(targetIp),
            localMac,
            localIp
        );

        ethernetPacket.PayloadPacket = arpPacket;

        PhysicalAddress macRes = null;

        device.OnPacketArrival += (sender, e) =>
        {
            var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
            var eth = packet.Extract<EthernetPacket>();
            var arp = packet.Extract<ArpPacket>();

            if (eth != null && arp != null &&
                arp.SenderProtocolAddress.ToString() == targetIp &&
                arp.Operation == ArpOperation.Response)
            {
                macRes = arp.SenderHardwareAddress;
                return;
            }
        };

        device.SendPacket(ethernetPacket);
        device.StartCapture();
        Thread.Sleep(2000);
        device.StopCapture();

        return macRes ?? throw new InvalidOperationException("[GetMacFromIP] MAC address not found for the target IP.");
    }

    /// <summary>
    /// Sends a SYN packet to the target IP and port.
    /// </summary>
    public static void SendSynPacket(ILiveDevice device, string targetIp, int targetPort, PhysicalAddress targetMac)
    {
        try
        {
            var random = new Random();
            var localIp = ((SharpPcap.LibPcap.LibPcapLiveDevice)device).Addresses
                        .FirstOrDefault(a =>
                            a.Addr.ipAddress != null &&
                            a.Addr.ipAddress.AddressFamily == AddressFamily.InterNetwork)
                        ?.Addr.ipAddress;
            var localMac = device.MacAddress;

            if (localIp == null)
            {
                throw new InvalidOperationException("[SendSynPacket] Local IP address not found.");
            }

            if (localMac == null)
            {
                throw new InvalidOperationException("[SendSynPacket] Local MAC address not found.");
            }

            // Packets structure
            var ethernetPacket = new EthernetPacket(
                localMac,
                targetMac,
                EthernetType.IPv4);

            var ipPacket = new IPv4Packet(localIp, IPAddress.Parse(targetIp))
            {
                TimeToLive = 64,
                Protocol = PacketDotNet.ProtocolType.Tcp
            };

            var tcpPacket = new TcpPacket(
                (ushort)random.Next(1024, 65535),
                (ushort)targetPort)
            {
                Synchronize = true,
                SequenceNumber = (uint)random.Next(),
                WindowSize = 8192, // 8 KB
            };

            // Build packets
            ipPacket.PayloadPacket = tcpPacket;
            ethernetPacket.PayloadPacket = ipPacket;

            // Update checksum
            tcpPacket.UpdateCalculatedValues();
            ipPacket.UpdateCalculatedValues();
            ethernetPacket.UpdateCalculatedValues();

            device.OnPacketArrival += (object sender, PacketCapture e) =>
            {
                var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
                var eth = packet.Extract<EthernetPacket>();
                var tcp = packet.Extract<TcpPacket>();

                // debugging...
                if (tcp.DestinationPort == targetPort)
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"[DEBUG] Packet captured: {packet} - {eth?.SourceHardwareAddress} -> {eth?.DestinationHardwareAddress}");
                    Console.ResetColor();
                }

                if (eth != null && tcp != null && eth.DestinationHardwareAddress == localMac &&
                    tcp.Synchronize && tcp.Acknowledgment)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"Port {targetPort} is open.");
                }
                else if (eth != null && tcp != null && eth.DestinationHardwareAddress == localMac && tcp.Reset)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Port {targetPort} is closed.");
                }
                else if (eth != null && tcp != null && eth.DestinationHardwareAddress == localMac && !tcp.Synchronize && !tcp.Reset)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"Port {targetPort} is filtered (no response).");
                }

                Console.ResetColor();
            };

            device.StartCapture();
            device.SendPacket(ethernetPacket);
            Thread.Sleep(5000);
            device.StopCapture();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"[SendSynPacket] {ex.Message}.");
        }
    }
}