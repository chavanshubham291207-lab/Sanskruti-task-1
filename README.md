# Educational Web PCAP Network Traffic Analyzer

This repository contains a professional Streamlit web application that parses offline packet inspection and protocol analysis files (`.pcap` or `.pcapng`). It is designed for educational cybersecurity training, network forensics learning, and protocol auditing.

---

## Features

* **File Upload:** Upload network captures (`.pcap` or `.pcapng`) directly through the browser.
* **Interactive Statistics Dashboard:** View real-time visual breakdown of packet counts, total network data size, and protocol distributions.
* **Network Conversations:** Map communication streams (Source IP vs Destination IP) and identify the most active hosts on the network.
* **Filtered Packet Log:** View individual packets with pagination/limits, protocol classification (TCP, UDP, ICMP, ARP), and details (sequence numbers, ports, flag previews).
* **Summary Report Export:** Copy or download a text-based analysis report (`.txt`) of your network capture.

---

## Local Setup & Run

### 1. Install Dependencies
Ensure you have the required Python modules installed:
```bash
pip install -r requirements.txt
```

*Note: For complete Scapy support, Windows users can optionally install [Npcap](https://npcap.com/) and Linux users can install `libpcap` (`sudo apt-get install libpcap-dev`), although offline parsing is supported natively by Scapy's fallback module.*

### 2. Run the Streamlit Dashboard
Start the local development server:
```bash
streamlit run app.py
```
A browser tab will automatically open at `http://localhost:8501`.

---

## Deployment on Render

This project is pre-configured for automated deployment to [Render](https://render.com).

### Option A: Using the Render Blueprint (`render.yaml`)
1. Push this project repository to your GitHub account.
2. In the Render Dashboard, click **New +** and select **Blueprint**.
3. Link your GitHub repository.
4. Render will automatically detect the `render.yaml` configuration and deploy the Streamlit service.

### Option B: Manual Web Service Deployment
If deploying manually:
1. In the Render Dashboard, click **New +** and select **Web Service**.
2. Link your GitHub repository.
3. Configure the following service settings:
   - **Environment:** `Python`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `streamlit run app.py --server.port $PORT --server.address 0.0.0.0`
4. Deploy the service.
