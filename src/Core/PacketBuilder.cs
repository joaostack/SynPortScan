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
    public static async Task<string> GetMacFromIP(ILiveDevice device, string targetIp, CancellationToken ct)
    {
        try
        {
            // search for local mac & local ip
            var localMac = device.MacAddress;
            var localIp = DeviceHelper.GetLocalIP(device);

            // create broadcast arp packet
            var arpPacket = new ArpPacket(
                ArpOperation.Request,
                PhysicalAddress.Parse("00-00-00-00-00-00"), //unknown mac
                IPAddress.Parse(targetIp),
                localMac,
                localIp
            );

            var ethernetPacket = new EthernetPacket(
                localMac,
                PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"), // Broadcast MAC
                EthernetType.Arp)
            {
                PayloadPacket = arpPacket
            };

            ethernetPacket.PayloadPacket = arpPacket;

            // wait for client response
            string macRes = null!;
            var tcs = new TaskCompletionSource<string>();
            PacketArrivalEventHandler handler = (sender, e) =>
            {
                var rawPacket = e.GetPacket();
                var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                var arp = packet.Extract<ArpPacket>();

                if (arp != null && arp.Operation == ArpOperation.Response && arp.SenderProtocolAddress.Equals(targetIp))
                {
                    tcs.TrySetResult(arp.SenderHardwareAddress.ToString());
                    return;
                }
            };

            device.Filter = "arp";
            device.OnPacketArrival += handler;
            device.StartCapture();
            device.SendPacket(ethernetPacket);

            try
            {
                device.OnPacketArrival += (object sender, PacketCapture e) =>
                {
                    var rawPacket = e.GetPacket();
                    var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                    var arpPacket = packet.Extract<ArpPacket>();

                    if (arpPacket != null)
                    {
                        if (arpPacket.Operation == ArpOperation.Response)
                            macRes = arpPacket.SenderHardwareAddress.ToString();
                    }

                };

                await Task.Delay(3000, ct);
            }
            catch (OperationCanceledException)
            {
                macRes = null!;
            }
            finally
            {
                device.OnPacketArrival -= handler;
                device.StopCapture();
            }

            return macRes ?? throw new InvalidOperationException($"MAC address not found for the target IP {targetIp}");
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"[GetMacFromIP] {ex.Message}");
        }
    }

    private static Dictionary<int, string> scannedPorts = new Dictionary<int, string>();
    /// <summary>
    /// Sends a SYN packet to the target IP and port.
    /// </summary>
    public static async Task SendSynPacket(ILiveDevice device, string targetIp, int targetPort, PhysicalAddress gatewayMac)
    {
        try
        {
            var random = new Random();
            var localIp = ((SharpPcap.LibPcap.LibPcapLiveDevice)device).Addresses
                        .FirstOrDefault(a =>
                            a.Addr?.ipAddress != null &&
                            a.Addr.ipAddress.AddressFamily == AddressFamily.InterNetwork)
                        ?.Addr?.ipAddress;
            var localMac = device.MacAddress;

            if (localIp == null) throw new InvalidOperationException("Local IP address not found.");
            if (localMac == null) throw new InvalidOperationException("Local MAC address not found.");

            var RANDOM_PORT = (ushort)random.Next(10000, 65535);

            // SYN PACKET 
            var ethernetPacket = new EthernetPacket(
                localMac,
                gatewayMac,
                EthernetType.IPv4);
            var tcpPacket = new TcpPacket(
                RANDOM_PORT,
                (ushort)targetPort)
            {
                Synchronize = true,
            };
            var ipPacket = new IPv4Packet(localIp, IPAddress.Parse(targetIp))
            {
                PayloadPacket = tcpPacket
            };
            ethernetPacket.PayloadPacket = ipPacket;

            // RST RESPONSE
            var ethernetPacket2 = new EthernetPacket(
                localMac,
                gatewayMac,
                EthernetType.IPv4);
            var tcpPacket2 = new TcpPacket(
                RANDOM_PORT,
                (ushort)targetPort)
            {
                Reset = true
            };
            var ipPacket2 = new IPv4Packet(localIp, IPAddress.Parse(targetIp))
            {
                PayloadPacket = tcpPacket2
            };
            ethernetPacket2.PayloadPacket = ipPacket2;

            // SYN Checksum
            tcpPacket.UpdateCalculatedValues();
            tcpPacket.UpdateTcpChecksum();
            ipPacket.UpdateCalculatedValues();
            ipPacket.UpdateIPChecksum();

            // RST Checksum
            tcpPacket2.UpdateCalculatedValues();
            tcpPacket2.UpdateTcpChecksum();
            ipPacket2.UpdateIPChecksum();
            ipPacket2.UpdateCalculatedValues();

            // sniff & handle server response
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

                            // close connection with RST flag
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

            device.Filter = $"tcp and host {targetIp}";
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
            device.StopCapture();
        }
    }
}
