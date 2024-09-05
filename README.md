# Packet Sniffer

This project is a network packet sniffer that captures and analyzes Ethernet frames and IPv4 packets using raw sockets. It dissects packets and provides detailed information for ICMP, TCP, and UDP protocols.

## Features

- **Ethernet Frame Analysis**: Captures and decodes Ethernet frames, showing source/destination MAC addresses and protocol type.
- **IPv4 Packet Analysis**: Extracts and displays the version, header length, TTL, source, and destination IP addresses.
- **ICMP Packet Parsing**: Handles ICMP packets and extracts type, code, and checksum information.
- **TCP Segment Parsing**: Extracts TCP segment details including source and destination ports, sequence numbers, and acknowledgment numbers.
- **UDP Segment Parsing**: Extracts UDP packet details including source and destination ports, and packet length.
- **Modular Design**: The code is organized into separate functions for each protocol layer, making it easy to extend or maintain.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Example Output](#example-output)
- [Contributing](#contributing)
- [License](#license)

## Installation
To run the packet sniffer, follow these steps:

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/packet-sniffer.git
   cd packet-sniffer
   
2. **Install Python (if not installed)**:
   ```bash
   Ensure you have Python 3.x installed. You can install Python by following instructions from the official Python website.
   
3. **Run the Sniffer: Since this code uses raw sockets, it requires superuser privileges. Run the script as root**:
   ```bash
   sudo python3 packet_sniffer.py

## Usage
The packet sniffer captures network traffic and decodes Ethernet, IPv4, ICMP, TCP, and UDP packets in real-time. After running the script, you will see details like:

- MAC Addresses
- IP Addresses
- Protocol Types
- TCP and UDP Ports
- ICMP Types

You can stop the script at any time by pressing `Ctrl+C`.

## Protocols Supported

- Ethernet (Layer 2)
- IPv4 (Layer 3)
- ICMP (Layer 3)
- TCP (Layer 4)
- UDP (Layer 4)
