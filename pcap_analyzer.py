#!/usr/bin/env python3
"""
PCAP Traffic Analyzer
--------------------
An educational cybersecurity tool to parse, filter, and analyze pre-captured 
network packets from a PCAP file using Scapy.

Features:
- Processes offline PCAP/PCAPNG capture files.
- Extracts Layer 2/3/4 packet metadata (timestamp, length, IPs, ports).
- Analyzes protocols (TCP, UDP, ICMP, ARP).
- Safely decodes packet payloads.
- Generates traffic statistics and summary reports.
"""

import os
import sys
import argparse
from datetime import datetime
from collections import Counter

# Import Scapy components safely
try:
    from scapy.all import PcapReader, IP, TCP, UDP, ARP, ICMP, Raw
except ImportError:
    print("Error: Scapy is not installed. Please install dependencies using: pip install -r requirements.txt")
    sys.exit(1)

def format_bytes(byte_count):
    """Format byte counts into human-readable strings (KB, MB)."""
    if byte_count < 1024:
        return f"{byte_count} B"
    elif byte_count < 1024 * 1024:
        return f"{byte_count / 1024:.2f} KB"
    else:
        return f"{byte_count / (1024 * 1024):.2f} MB"

def safe_payload_preview(payload, max_len=64):
    """Safely decode and format packet payload into a printable ASCII/hex string."""
    if not payload:
        return "[No Payload]"
    
    # Try to decode as ASCII, replacing non-printable characters
    ascii_chars = []
    for b in payload:
        if 32 <= b <= 126:
            ascii_chars.append(chr(b))
        else:
            ascii_chars.append('.')
            
    ascii_str = "".join(ascii_chars)
    
    # Truncate if it exceeds maximum preview length
    if len(ascii_str) > max_len:
        return ascii_str[:max_len] + "..."
    return ascii_str

def parse_packet(packet):
    """Extract protocol metadata from a single Scapy packet."""
    pkt_info = {
        "timestamp": float(packet.time),
        "length": len(packet),
        "src_ip": "N/A",
        "dst_ip": "N/A",
        "protocol": "Other",
        "src_port": "N/A",
        "dst_port": "N/A",
        "details": "",
        "payload": None
    }
    
    # Address Resolution Protocol (ARP) - Layer 2/3
    if packet.haslayer(ARP):
        arp_layer = packet.getlayer(ARP)
        pkt_info["protocol"] = "ARP"
        pkt_info["src_ip"] = arp_layer.psrc
        pkt_info["dst_ip"] = arp_layer.pdst
        op_type = "Request" if arp_layer.op == 1 else "Reply" if arp_layer.op == 2 else f"Op:{arp_layer.op}"
        pkt_info["details"] = f"ARP {op_type} | Sender MAC: {arp_layer.hwsrc} -> Target MAC: {arp_layer.hwdst}"
        
    # Internet Protocol (IP) - Layer 3
    elif packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        pkt_info["src_ip"] = ip_layer.src
        pkt_info["dst_ip"] = ip_layer.dst
        
        # Transmission Control Protocol (TCP) - Layer 4
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            pkt_info["protocol"] = "TCP"
            pkt_info["src_port"] = tcp_layer.sport
            pkt_info["dst_port"] = tcp_layer.dport
            flags = tcp_layer.underlayer.sprintf('%TCP.flags%')
            pkt_info["details"] = f"Seq: {tcp_layer.seq} | Ack: {tcp_layer.ack} | Flags: {flags}"
            
        # User Datagram Protocol (UDP) - Layer 4
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            pkt_info["protocol"] = "UDP"
            pkt_info["src_port"] = udp_layer.sport
            pkt_info["dst_port"] = udp_layer.dport
            pkt_info["details"] = f"Len: {udp_layer.len}"
            
        # Internet Control Message Protocol (ICMP) - Layer 4
        elif packet.haslayer(ICMP):
            icmp_layer = packet.getlayer(ICMP)
            pkt_info["protocol"] = "ICMP"
            pkt_info["details"] = f"Type: {icmp_layer.type} | Code: {icmp_layer.code}"
        
        else:
            pkt_info["protocol"] = "IP (Other)"
            pkt_info["details"] = f"Proto: {ip_layer.proto}"

    # Extract raw data payload if present
    if packet.haslayer(Raw):
        pkt_info["payload"] = packet.getlayer(Raw).load

    return pkt_info

def print_packet_line(pkt, count):
    """Print parsed packet info in a clean, human-readable format."""
    time_str = datetime.fromtimestamp(pkt["timestamp"]).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    # Base layout
    header = f"[{count:04d}] {time_str} | {pkt['protocol']:<6} | Size: {pkt['length']:>4} B"
    addressing = f"{pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']}"
    
    print(f"{header} | {addressing:<45}")
    if pkt['details']:
        print(f"       Details: {pkt['details']}")
    if pkt['payload']:
        preview = safe_payload_preview(pkt['payload'])
        print(f"       Payload: {preview}")
    print("-" * 80)

def main():
    parser = argparse.ArgumentParser(
        description="PCAP Traffic Analyzer - Educational Cybersecurity Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example Usage:
  python pcap_analyzer.py capture.pcap
  python pcap_analyzer.py capture.pcap --filter TCP --limit 50
  python pcap_analyzer.py capture.pcap --output summary_report.txt
"""
    )
    parser.add_argument("pcap_file", help="Path to the PCAP or PCAPNG capture file to analyze")
    parser.add_argument("-f", "--filter", choices=["TCP", "UDP", "ICMP", "ARP", "ALL"], default="ALL",
                        help="Filter packets by specific protocol (default: ALL)")
    parser.add_argument("-l", "--limit", type=int, default=None,
                        help="Limit the number of packets displayed in the console")
    parser.add_argument("-o", "--output", help="Save the summary statistics report to this text file")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.pcap_file):
        print(f"Error: The target PCAP file '{args.pcap_file}' does not exist.")
        sys.exit(1)
        
    print("=" * 80)
    print("                      PCAP OFFLINE TRAFFIC ANALYZER")
    print("=" * 80)
    print(f"Target Capture File: {args.pcap_file}")
    print(f"Protocol Filter:     {args.filter}")
    print(f"Display Limit:       {args.limit if args.limit else 'Unlimited'}")
    print("=" * 80)
    print("")

    # Statistics tracking variables
    total_packets = 0
    filtered_packets_count = 0
    total_bytes = 0
    
    protocol_counter = Counter()
    ip_src_counter = Counter()
    ip_dst_counter = Counter()
    ip_pairs_counter = Counter()
    
    # Process the PCAP file
    try:
        with PcapReader(args.pcap_file) as pcap_reader:
            for raw_packet in pcap_reader:
                total_packets += 1
                
                # Parse layers
                pkt = parse_packet(raw_packet)
                
                # Update statistics
                protocol_counter[pkt["protocol"]] += 1
                total_bytes += pkt["length"]
                if pkt["src_ip"] != "N/A":
                    ip_src_counter[pkt["src_ip"]] += 1
                if pkt["dst_ip"] != "N/A":
                    ip_dst_counter[pkt["dst_ip"]] += 1
                if pkt["src_ip"] != "N/A" and pkt["dst_ip"] != "N/A":
                    ip_pairs_counter[(pkt["src_ip"], pkt["dst_ip"])] += 1
                
                # Apply filter
                if args.filter != "ALL" and pkt["protocol"] != args.filter:
                    continue
                
                filtered_packets_count += 1
                
                # Display individual packets within limit
                if args.limit is None or filtered_packets_count <= args.limit:
                    print_packet_line(pkt, filtered_packets_count)
                    
    except Exception as e:
        print(f"Fatal Error parsing PCAP: {e}")
        sys.exit(1)

    # Calculate report output
    summary_lines = []
    summary_lines.append("=" * 80)
    summary_lines.append("                           TRAFFIC SUMMARY REPORT")
    summary_lines.append("=" * 80)
    summary_lines.append(f"Analysis Time:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    summary_lines.append(f"File Handled:        {args.pcap_file}")
    summary_lines.append(f"Total Packets:       {total_packets}")
    summary_lines.append(f"Total Traffic Size:  {format_bytes(total_bytes)}")
    summary_lines.append("-" * 80)
    
    # Protocol Breakdown
    summary_lines.append("Protocol Distribution:")
    for proto, count in protocol_counter.items():
        percentage = (count / total_packets) * 100 if total_packets > 0 else 0
        summary_lines.append(f"  - {proto:<10} {count:>6} packets ({percentage:.2f}%)")
    summary_lines.append("-" * 80)
    
    # Top active IP addresses
    summary_lines.append("Top 5 Source IP Addresses:")
    for ip, count in ip_src_counter.most_common(5):
        summary_lines.append(f"  - {ip:<15} {count:>6} packets")
        
    summary_lines.append("\nTop 5 Destination IP Addresses:")
    for ip, count in ip_dst_counter.most_common(5):
        summary_lines.append(f"  - {ip:<15} {count:>6} packets")
    summary_lines.append("-" * 80)
    
    # Top conversations
    summary_lines.append("Top 5 Conversations (Source -> Destination):")
    for (src, dst), count in ip_pairs_counter.most_common(5):
        summary_lines.append(f"  - {src:<15} -> {dst:<15} : {count} packets")
    summary_lines.append("=" * 80)

    # Output report to console
    print("\n".join(summary_lines))
    
    # Save report if output file is specified
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write("\n".join(summary_lines))
            print(f"\n[Info] Summary report successfully exported to '{args.output}'")
        except IOError as e:
            print(f"\n[Error] Failed to write report to '{args.output}': {e}")

if __name__ == "__main__":
    main()
