import streamlit as st
import pandas as pd
import tempfile
import os
from datetime import datetime
from collections import Counter

# Safe imports for Scapy
try:
    from scapy.all import PcapReader, IP, TCP, UDP, ARP, ICMP, Raw
except ImportError:
    st.error("Scapy is not installed. Please add it to your environment.")

# Set Streamlit Page Configuration
st.set_page_config(
    page_title="Educational PCAP Traffic Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# App Title & Description
st.title("🛡️ Educational PCAP Traffic Analyzer")
st.markdown("""
This web application parses pre-captured network traffic files (`.pcap` or `.pcapng`) using Scapy.
It generates visual protocol statistics, traces communication streams, and builds reports for educational cybersecurity labs.
""")

def format_bytes(byte_count):
    if byte_count < 1024:
        return f"{byte_count} B"
    elif byte_count < 1024 * 1024:
        return f"{byte_count / 1024:.2f} KB"
    else:
        return f"{byte_count / (1024 * 1024):.2f} MB"

def safe_payload_preview(payload, max_len=64):
    if not payload:
        return "[No Payload]"
    ascii_chars = [chr(b) if 32 <= b <= 126 else '.' for b in payload]
    ascii_str = "".join(ascii_chars)
    if len(ascii_str) > max_len:
        return ascii_str[:max_len] + "..."
    return ascii_str

def parse_packet(packet):
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
    
    if packet.haslayer(ARP):
        arp_layer = packet.getlayer(ARP)
        pkt_info["protocol"] = "ARP"
        pkt_info["src_ip"] = arp_layer.psrc
        pkt_info["dst_ip"] = arp_layer.pdst
        op_type = "Request" if arp_layer.op == 1 else "Reply" if arp_layer.op == 2 else f"Op:{arp_layer.op}"
        pkt_info["details"] = f"ARP {op_type} | MAC: {arp_layer.hwsrc} -> {arp_layer.hwdst}"
        
    elif packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        pkt_info["src_ip"] = ip_layer.src
        pkt_info["dst_ip"] = ip_layer.dst
        
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            pkt_info["protocol"] = "TCP"
            pkt_info["src_port"] = str(tcp_layer.sport)
            pkt_info["dst_port"] = str(tcp_layer.dport)
            flags = tcp_layer.underlayer.sprintf('%TCP.flags%')
            pkt_info["details"] = f"Seq: {tcp_layer.seq} | Ack: {tcp_layer.ack} | Flags: {flags}"
            
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            pkt_info["protocol"] = "UDP"
            pkt_info["src_port"] = str(udp_layer.sport)
            pkt_info["dst_port"] = str(udp_layer.dport)
            pkt_info["details"] = f"Len: {udp_layer.len}"
            
        elif packet.haslayer(ICMP):
            icmp_layer = packet.getlayer(ICMP)
            pkt_info["protocol"] = "ICMP"
            pkt_info["details"] = f"Type: {icmp_layer.type} | Code: {icmp_layer.code}"
        
        else:
            pkt_info["protocol"] = "IP (Other)"
            pkt_info["details"] = f"Proto: {ip_layer.proto}"

    if packet.haslayer(Raw):
        pkt_info["payload"] = packet.getlayer(Raw).load

    return pkt_info

# Sidebar Configuration
st.sidebar.header("📁 File Upload & Configuration")
uploaded_file = st.sidebar.file_uploader("Upload a PCAP / PCAPNG File", type=["pcap", "pcapng"])

protocol_filter = st.sidebar.selectbox(
    "Filter Protocol",
    ["ALL", "TCP", "UDP", "ICMP", "ARP"]
)

search_ip = st.sidebar.text_input("Filter by IP Address (Src/Dst)", "")

max_rows = st.sidebar.slider(
    "Max Packets to Display in Table",
    min_value=10,
    max_value=1000,
    value=100,
    step=10
)

if uploaded_file is not None:
    # Save uploaded file to a temporary file on disk
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as temp_pcap:
        temp_pcap.write(uploaded_file.read())
        temp_pcap_path = temp_pcap.name
    
    # Process packet data
    packets_list = []
    total_packets = 0
    total_bytes = 0
    
    protocol_counter = Counter()
    ip_src_counter = Counter()
    ip_dst_counter = Counter()
    ip_pairs_counter = Counter()
    
    try:
        with st.spinner("Parsing packet capture..."):
            with PcapReader(temp_pcap_path) as pcap_reader:
                for raw_packet in pcap_reader:
                    total_packets += 1
                    pkt = parse_packet(raw_packet)
                    
                    # Update global statistics
                    protocol_counter[pkt["protocol"]] += 1
                    total_bytes += pkt["length"]
                    if pkt["src_ip"] != "N/A":
                        ip_src_counter[pkt["src_ip"]] += 1
                    if pkt["dst_ip"] != "N/A":
                        ip_dst_counter[pkt["dst_ip"]] += 1
                    if pkt["src_ip"] != "N/A" and pkt["dst_ip"] != "N/A":
                        ip_pairs_counter[(pkt["src_ip"], pkt["dst_ip"])] += 1
                    
                    # Apply search and protocol filters
                    if protocol_filter != "ALL" and pkt["protocol"] != protocol_filter:
                        continue
                    if search_ip and (search_ip not in pkt["src_ip"] and search_ip not in pkt["dst_ip"]):
                        continue
                    
                    packets_list.append(pkt)
        
        # Clean up temp file
        os.remove(temp_pcap_path)
        
    except Exception as e:
        st.error(f"Error parsing file: {e}")
        if os.path.exists(temp_pcap_path):
            os.remove(temp_pcap_path)
        st.stop()

    # Layout Metrics Dashboard
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Packets", f"{total_packets:,}")
    with col2:
        st.metric("Filtered Packets", f"{len(packets_list):,}")
    with col3:
        st.metric("Total Capture Size", format_bytes(total_bytes))

    # Tabs layout
    tab1, tab2, tab3 = st.tabs(["📊 Protocol Statistics", "🔍 Packet Inspector", "📄 Summary Report"])

    with tab1:
        st.subheader("Protocol Distribution")
        if protocol_counter:
            proto_df = pd.DataFrame(protocol_counter.items(), columns=["Protocol", "Count"])
            
            col_chart, col_table = st.columns([2, 1])
            with col_chart:
                st.bar_chart(proto_df.set_index("Protocol"))
            with col_table:
                st.dataframe(proto_df, use_container_width=True)
        else:
            st.info("No protocol data found.")

        # Top IP addresses
        st.subheader("Network Communication Volume")
        col_src, col_dst = st.columns(2)
        with col_src:
            st.markdown("**Top Source IP Addresses**")
            src_df = pd.DataFrame(ip_src_counter.most_common(5), columns=["IP Address", "Count"])
            st.dataframe(src_df, use_container_width=True)
        with col_dst:
            st.markdown("**Top Destination IP Addresses**")
            dst_df = pd.DataFrame(ip_dst_counter.most_common(5), columns=["IP Address", "Count"])
            st.dataframe(dst_df, use_container_width=True)

        st.subheader("Top Conversations")
        conv_items = [(f"{src} -> {dst}", count) for (src, dst), count in ip_pairs_counter.most_common(5)]
        if conv_items:
            conv_df = pd.DataFrame(conv_items, columns=["Stream", "Packet Count"])
            st.dataframe(conv_df, use_container_width=True)
        else:
            st.info("No communication streams detected.")

    with tab2:
        st.subheader(f"Filtered Packets Log (Showing top {min(len(packets_list), max_rows)})")
        if packets_list:
            display_data = []
            for i, p in enumerate(packets_list[:max_rows]):
                dt_object = datetime.fromtimestamp(p["timestamp"])
                time_str = dt_object.strftime('%H:%M:%S.%f')[:-3]
                display_data.append({
                    "Index": i + 1,
                    "Time": time_str,
                    "Proto": p["protocol"],
                    "Src IP": p["src_ip"],
                    "Src Port": p["src_port"],
                    "Dst IP": p["dst_ip"],
                    "Dst Port": p["dst_port"],
                    "Length (B)": p["length"],
                    "Details": p["details"],
                    "Payload Preview": safe_payload_preview(p["payload"])
                })
            
            df_display = pd.DataFrame(display_data)
            st.dataframe(df_display, use_container_width=True, hide_index=True)
        else:
            st.info("No packets matched the current filters.")

    with tab3:
        st.subheader("Generated Text Report")
        
        # Build report text
        report_text = f"""================================================================================
                           TRAFFIC SUMMARY REPORT
================================================================================
Analysis Time:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
File Handled:        {uploaded_file.name}
Total Packets:       {total_packets}
Total Traffic Size:  {format_bytes(total_bytes)}
--------------------------------------------------------------------------------
Protocol Distribution:"""
        for proto, count in protocol_counter.items():
            percentage = (count / total_packets) * 100 if total_packets > 0 else 0
            report_text += f"\n  - {proto:<10} {count:>6} packets ({percentage:.2f}%)"
            
        report_text += "\n--------------------------------------------------------------------------------\nTop 5 Source IP Addresses:"
        for ip, count in ip_src_counter.most_common(5):
            report_text += f"\n  - {ip:<15} {count:>6} packets"
            
        report_text += "\n\nTop 5 Destination IP Addresses:"
        for ip, count in ip_dst_counter.most_common(5):
            report_text += f"\n  - {ip:<15} {count:>6} packets"
            
        report_text += "\n--------------------------------------------------------------------------------\nTop 5 Conversations (Source -> Destination):"
        for (src, dst), count in ip_pairs_counter.most_common(5):
            report_text += f"\n  - {src:<15} -> {dst:<15} : {count} packets"
        report_text += "\n================================================================================"

        st.text_area("Report Preview", value=report_text, height=400)
        
        st.download_button(
            label="Download Summary Report (.txt)",
            data=report_text,
            file_name=f"pcap_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )
else:
    st.info("Please upload a PCAP or PCAPNG capture file in the sidebar to begin analysis.")
