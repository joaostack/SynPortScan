namespace SynPortScan.Core;

using SharpPcap;
using PacketDotNet;
using System.Net.NetworkInformation;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

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
    public static async Task<PhysicalAddress> GetMacFromIP(ILiveDevice device, string targetIp, CancellationToken ct)
    {
        try
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

            device.StartCapture();
            device.SendPacket(ethernetPacket);
            await Task.Delay(2000);
            device.StopCapture();

            return macRes ?? throw new InvalidOperationException("[GetMacFromIP] MAC address not found for the target IP.");
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"[GetMacFromIP] {ex.Message}.");
        }
    }
    /// <summary>
    /// Sends a SYN packet to the target IP and port.
    /// </summary>
    public static async Task SendSynPacket(ILiveDevice device, string targetIp, int targetPort, PhysicalAddress gatewayMac, int threads, CancellationToken ct)
    {
        SemaphoreSlim semaphoreSlim = new SemaphoreSlim(threads);

        try
        {
            await semaphoreSlim.WaitAsync();

            // Set BPF Filter
            device.Filter = $"tcp and host {targetIp}";

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

            var RANDOM_PORT = (ushort)random.Next(10000, 65535);

            // Packets structure
            var ethernetPacket = new EthernetPacket(
                localMac,
                gatewayMac,
                EthernetType.IPv4);

            // Normal Connection
            var tcpPacket = new TcpPacket(
                RANDOM_PORT,
                (ushort)targetPort);
            tcpPacket.Synchronize = true;
            tcpPacket.WindowSize = 8192;
            tcpPacket.SequenceNumber = (uint)random.Next();

            var ipPacket = new IPv4Packet(localIp, IPAddress.Parse(targetIp));
            ipPacket.TimeToLive = 64;
            ipPacket.PayloadPacket = tcpPacket;

            // Update checksums
            tcpPacket.UpdateCalculatedValues();
            tcpPacket.UpdateTcpChecksum();
            ipPacket.UpdateCalculatedValues();
            ipPacket.UpdateIPChecksum();

            // Set the Ethernet packet payload to the IP packet
            ethernetPacket.PayloadPacket = ipPacket;

            // RST response
            var ethernetPacket2 = new EthernetPacket(
                localMac,
                gatewayMac,
                EthernetType.IPv4);

            var tcpPacket2 = new TcpPacket(
                RANDOM_PORT,
                (ushort)targetPort);
            tcpPacket2.Reset = true;
            tcpPacket2.WindowSize = 8192;
            tcpPacket2.SequenceNumber = (uint)random.Next();

            var ipPacket2 = new IPv4Packet(localIp, IPAddress.Parse(targetIp));
            ipPacket2.TimeToLive = 64;
            ipPacket2.PayloadPacket = tcpPacket2;

            // Update RST Packet Checksums
            tcpPacket2.UpdateCalculatedValues();
            tcpPacket2.UpdateTcpChecksum();
            ipPacket2.UpdateIPChecksum();
            ipPacket2.UpdateCalculatedValues();

            ethernetPacket2.PayloadPacket = ipPacket2;

            Dictionary<int, string> scannedPorts = new Dictionary<int, string>();

            device.OnPacketArrival += (object sender, PacketCapture e) =>
            {
                var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
                var eth = packet.Extract<EthernetPacket>();
                var tcp = packet.Extract<TcpPacket>();
                var ip = packet.Extract<IPv4Packet>();

                if (tcp != null && ip != null && tcp.SourcePort == targetPort)
                {
                    if (!scannedPorts.ContainsKey(targetPort))
                    {
                        if (tcp.Synchronize && tcp.Acknowledgment)
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"Port {targetPort} is open.");
                            scannedPorts[targetPort] = "open";
                            device.SendPacket(ethernetPacket2);
                        }
                        else if (tcp.Reset || (tcp.Reset && tcp.Acknowledgment))
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"Port {targetPort} is closed.");
                            scannedPorts[targetPort] = "closed";
                        }
                        else if (!tcp.Reset && !tcp.Acknowledgment)
                        {
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine($"Port {targetPort} is filtered.");
                            scannedPorts[targetPort] = "filtered";
                        }
                    }
                }

                Console.ResetColor();
            };

            device.StartCapture();
            device.SendPacket(ethernetPacket);
            await Task.Delay(3000);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"[SendSynPacket] {ex.Message}.");
        }
        finally
        {
            semaphoreSlim.Release();
            device.StopCapture();
        }
    }
}