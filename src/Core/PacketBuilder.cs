using System.Collections.Concurrent;

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
    public static async Task<string> GetMacFromIP(ILiveDevice device, string targetIp)
    {
        var localMac = device.MacAddress;
        var localIp = DeviceHelper.GetLocalIP(device);

        var arpPacket = new ArpPacket(ArpOperation.Request,
            PhysicalAddress.Parse("00-00-00-00-00-00"),
            IPAddress.Parse(targetIp),
            localMac,
            localIp);

        var ethPacket = new EthernetPacket(localMac, PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"), EthernetType.Arp)
        {
            PayloadPacket = arpPacket
        };

        var tcs = new TaskCompletionSource<string>();

        PacketArrivalEventHandler handler = null!;
        handler = (sender, e) =>
        {
            var pkt = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
            var arp = pkt.Extract<ArpPacket>();
            if (arp?.Operation == ArpOperation.Response &&
                arp.SenderProtocolAddress.ToString() == targetIp)
            {
                tcs.TrySetResult(arp.SenderHardwareAddress.ToString());
                device.OnPacketArrival -= handler;
            }
        };

        device.Filter = "arp";
        device.OnPacketArrival += handler;
        device.StartCapture();
        device.SendPacket(ethPacket);

        var timeoutTask = Task.Delay(1500);
        var completed = await Task.WhenAny(tcs.Task, timeoutTask);

        device.StopCapture();
        if (completed == timeoutTask)
            throw new InvalidOperationException("ARP timeout");

        return await tcs.Task;
    }

    /// <summary>
    /// Sends a SYN packet to the target IP and port.
    /// </summary>
    private static ConcurrentDictionary<ushort, PendingScan> _pendingScans = new();

    public static async Task SendSynPacket(ILiveDevice device, string targetIp, int targetPort, bool verbose,
        PhysicalAddress gatewayMac, CancellationToken cancellationToken)
    {
        try
        {
            var localIp = ((SharpPcap.LibPcap.LibPcapLiveDevice)device).Addresses
                .FirstOrDefault(a =>
                    a.Addr?.ipAddress != null &&
                    a.Addr.ipAddress.AddressFamily == AddressFamily.InterNetwork)
                ?.Addr?.ipAddress;
            var localMac = device.MacAddress;

            if (localIp == null) throw new InvalidOperationException("Local IP address not found.");
            if (localMac == null) throw new InvalidOperationException("Local MAC address not found.");

            ushort sourcePort = NextSourcePort();

            // SYN PACKET 
            var ethernetPacket = new EthernetPacket(
                localMac,
                gatewayMac,
                EthernetType.IPv4);
            var tcpPacket = new TcpPacket(
                sourcePort,
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
                sourcePort,
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

            var scan = new PendingScan
            {
                TargetPort = targetPort,
                SourcePort = sourcePort,
                Verbose = verbose,
                RstPacket = ethernetPacket2
            };

            _pendingScans[sourcePort] = scan;

            device.SendPacket(ethernetPacket);

            var completed = await Task.WhenAny(
                scan.Completion.Task,
                Task.Delay(1500, cancellationToken));

            if (completed != scan.Completion.Task)
                _pendingScans.TryRemove(sourcePort, out _);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"[SendSynPacket] {ex.Message}.");
        }
    }

    public static void PacketArrival(object? sender, PacketCapture e)
    {
        var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
        var tcp = packet.Extract<TcpPacket>();
        var ip = packet.Extract<IPv4Packet>();

        if (tcp == null || ip == null) return;

        if (!_pendingScans.TryRemove(tcp.DestinationPort, out var scan))
            return;

        if (tcp.Synchronize && tcp.Acknowledgment)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"Port {scan.TargetPort} open");

            ((ILiveDevice)sender!).SendPacket(scan.RstPacket);

            scan.Completion.TrySetResult("open");
        }
        else if (tcp.Reset)
        {
            if (scan.Verbose)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Port {scan.TargetPort} closed");
            }

            scan.Completion.TrySetResult("closed");
        }

        _pendingScans.TryRemove(tcp.DestinationPort, out _);

        Console.ResetColor();
    }

    private static int _nextPort = 40000;

    private static ushort NextSourcePort()
    {
        var port = Interlocked.Increment(ref _nextPort);

        if (port > 65000)
        {
            Interlocked.Exchange(ref _nextPort, 40000);
            port = Interlocked.Increment(ref _nextPort);
        }

        return (ushort)port;
    }
}

public class PendingScan
{
    public int TargetPort { get; init; }
    public ushort SourcePort { get; init; }

    public EthernetPacket RstPacket { get; init; } = null!;

    public bool Verbose { get; init; }

    public TaskCompletionSource<string> Completion { get; } = new();
}