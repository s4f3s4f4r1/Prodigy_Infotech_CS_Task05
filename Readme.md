# Packet Analyzer

A simple Python-based network packet sniffer that captures and analyzes network traffic over a specified interface.

### s4f3s4f4r1 
Developer of this Packet Analyzer tool

## Overview

The Packet Analyzer allows you to monitor and capture network traffic for analysis. It supports both TCP and UDP packets, and displays details such as source and destination IP addresses, ports, protocols, and raw data.

## Features

- **Supports TCP and UDP Protocols**: Captures both types of traffic.
- **Interface Selection**: Allows you to choose the network interface for sniffing (e.g., `eth0`, `wlan0`).
- **Real-time Packet Monitoring**: Displays network traffic in real-time, showing:
  - Source and destination IP addresses
  - Source and destination ports
  - Protocol type (TCP/UDP)
  - Raw packet data

## How to Use

1. Clone the repository:

    ```bash
    git clone <repository-url>
    ```

2. Navigate to the project directory:

    ```bash
    cd Task01_Packet_Analyzer
    ```

3. Run the packet analyzer script with `sudo`:

    ```bash
    sudo python3 Task_05_Packet_Analyzer.py
    ```

4. When prompted, enter the network interface to sniff on (e.g., `wlan0`, `eth0`):

    ```bash
    Enter the interface to sniff (e.g., wlan0, eth0): wlan0
    ```

5. The tool will start capturing packets and display the following information:

    - Source IP
    - Destination IP
    - Source Port
    - Destination Port
    - Protocol (TCP/UDP)
    - Raw packet data

## Sample Output

```plaintext
Starting packet sniffer on interface: wlan0

Source IP: 10.0.0.2  Destination IP: 216.58.203.10  Protocol: 17
UDP Packet - Source Port: 34644  Destination Port: 443
Raw Data: Y+hf=r1y0@

Source IP: 10.0.0.2  Destination IP: 104.16.102.112  Protocol: 6
TCP Packet - Source Port: 53366  Destination Port: 443
Raw Data: DiE8#@YNMCMUL

Source IP: 172.64.155.20  Destination IP: 10.0.0.2  Protocol: 6
TCP Packet - Source Port: 443  Destination Port: 141618
Raw Data: aB^_==h@

...
