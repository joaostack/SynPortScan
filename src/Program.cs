namespace SynPortScan;

using System;
using SynPortScan.Core;

/// <summary>
/// SynPortScan application.
/// </summary>
public class Program
{
    /// <summary>
    /// SynPortScan args.
    /// </summary>
    /// <param name="ip">Target IP</param>
    static void Main(string ip)
    {
        Console.WriteLine("SynPortScan is a SYN port scanner.");

        PacketBuilder.GetMacFromIP(null, ip);
    }
}