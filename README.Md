# Packet Sniffer 

This repository contains a simple Python-based packet sniffer that captures and analyzes network packets. It displays information such as source and destination IP addresses, protocols, and payload data. This tool is designed for educational purposes and must only be used in environments where you have explicit permission.

## Features

- **Ethernet Frame Analysis**: Extracts and displays source/destination MAC addresses and protocol type.
- **IPv4 Packet Analysis**: Displays version, header length, TTL, protocol, source, and destination IPs.
- **Protocol Support**:
  - ICMP: Extracts type, code, and checksum.
  - TCP: Displays source/destination ports, sequence, acknowledgment, and flags.
  - UDP: Extracts source/destination ports and length.
- **Payload Analysis**: Outputs raw data for unsupported protocols.

## Requirements

- Python 3.6 or higher
- Administrative privileges (required to capture raw network packets)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/packet-sniffer.git
   ```
2. Navigate to the project directory:
   ```bash
   cd packet-sniffer
   ```
3. Run the script:
   ```bash
   python packet_sniffer.py
   ```

## Usage

1. Start the program:
   ```bash
   sudo python packet_sniffer.py  # Use 'sudo' or run as Administrator
   ```
2. The program will listen for packets and display details in real-time.
3. Press `Ctrl+C` to stop the program.

### Example Output

```
Packet Sniffer (Educational Use Only)
Listening for packets...

Ethernet Frame:
  Destination: FF:FF:FF:FF:FF:FF, Source: 00:1A:2B:3C:4D:5E, Protocol: 8
  IPv4 Packet:
    Version: 4, Header Length: 20, TTL: 64
    Protocol: 6, Source: 192.168.1.100, Target: 93.184.216.34
    TCP Segment:
      Source Port: 54321, Destination Port: 80
      Sequence: 123456789, Acknowledgment: 987654321
      Flags: {'URG': 0, 'ACK': 1, 'PSH': 1, 'RST': 0, 'SYN': 0, 'FIN': 0}
```

## Ethical Use

1. **Authorized Use Only**: This tool must only be used with explicit permission from the network owner.
2. **Educational Intent**: This program is designed for learning purposes, such as understanding network protocols and traffic analysis.
3. **Legal Compliance**: Ensure compliance with all local laws and regulations regarding network monitoring.

## File Structure

- `packet_sniffer.py`: The main script for packet sniffing and analysis.
- `README.md`: Documentation for the project.

