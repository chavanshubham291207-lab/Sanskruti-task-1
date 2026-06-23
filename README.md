# Offline PCAP Network Traffic Analyzer

This repository contains a professional offline packet inspection and protocol analysis program built in Python using Scapy. It is designed for educational cybersecurity training, network forensics learning, and protocol auditing.

## Project Structure

```text
basic-network-sniffer/ (or sanskruti task 1/)
├── pcap_analyzer.py      # The main Python script containing analyzer logic
├── requirements.txt      # List of dependencies (Scapy)
└── README.md             # Theoretical documentation and usage guide
```

---

## Technical Concepts

### The TCP/IP Protocol Stack & Encapsulation
Data sent over a network moves down the TCP/IP layers on the sender's device, with each layer prepending header metadata (encapsulation). On the receiving end, the layers are parsed and stripped (decapsulation).

```
+-----------------------------------+-------------------------------------------+
| OSI / TCP/IP Layer                | Headers Inspected                         |
+-----------------------------------+-------------------------------------------+
| Application (Data)                | Raw Payload (parsed safely as ASCII)      |
| Transport                         | TCP (Ports, Seq, Ack, Flags), UDP (Ports) |
| Network                           | IP (Source/Destination IP addresses)      |
| Data Link                         | ARP (MAC addresses, Opcode)               |
+-----------------------------------+-------------------------------------------+
```

1. **Layer 2 (Data Link - ARP):** ARP maps 32-bit IP addresses to 48-bit physical MAC addresses. The header specifies whether the packet is a "Request" (who has this IP?) or a "Reply" (I have it, here is my MAC).
2. **Layer 3 (Network - IP):** IP addresses route packets between networks. Key fields include Source IP, Destination IP, and the protocol type (indicating whether Layer 4 contains TCP, UDP, etc.).
3. **Layer 4 (Transport - TCP/UDP/ICMP):**
   - **TCP:** A connection-oriented protocol that ensures ordered, reliable packet delivery. It uses Sequence and Acknowledgment numbers along with Flags (SYN, ACK, FIN, RST, PSH, URG) to maintain session state.
   - **UDP:** A lightweight, connectionless protocol used where speed is prioritized over reliability.
   - **ICMP:** Used for network diagnostic messages (e.g., Echo Request/Reply used by ping).

---

## Installation & Setup

### 1. Prerequisites (Capture Drivers)
To parse low-level headers and dependencies:
*   **Windows:** Install [Npcap](https://npcap.com/). During installation, keep the default options selected (you do *not* need to run in loopback or WinPcap compatibility mode unless using legacy applications, but Scapy works best with Npcap fully active).
*   **Linux:** Install `libpcap` using your package manager.
    ```bash
    sudo apt-get update && sudo apt-get install libpcap-dev -y
    ```
*   **macOS:** macOS comes with `libpcap` pre-installed.

### 2. Install Project Dependencies
Run the following command to install the required Python libraries:
```bash
pip install -r requirements.txt
```

---

## Usage Instructions

The script processes pre-captured traffic saved in `.pcap` or `.pcapng` format.

### Command Options
```bash
python pcap_analyzer.py --help
```

### Examples

1. **Basic Analysis:**
   Read and analyze all packets in a capture file:
   ```bash
   python pcap_analyzer.py capture.pcap
   ```

2. **Filter by Protocol:**
   Inspect only TCP packets:
   ```bash
   python pcap_analyzer.py capture.pcap --filter TCP
   ```

3. **Limit Output:**
   Limit console display to the first 10 packets:
   ```bash
   python pcap_analyzer.py capture.pcap --limit 10
   ```

4. **Export a Summary Report:**
   Perform analysis and export the statistics report to a text file:
   ```bash
   python pcap_analyzer.py capture.pcap --output analysis_report.txt
   ```
