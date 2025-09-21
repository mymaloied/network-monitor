# Network Monitor

A Python-based network packet sniffer with filtering capabilities and multiple output formats.

## Features

- **Packet Capture**: Capture network packets with customizable count (1-1000)
- **Advanced Filtering**: 18 different filter options including protocol-based and host-based filters
- **Multiple Output Formats**: Save packets as text logs, PCAP files, or both
- **Log Management**: Built-in log clearing functionality
- **Dependency Checking**: Automatic validation of required dependencies and permissions

## Requirements

- Python 3.6+
- Scapy library
- Administrator/root privileges (required for packet capture)
- Npcap (Windows) or libpcap (Linux/macOS)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/mymaloied/network-monitor.git
cd network-monitor
```

2. Install required dependencies:
```bash
pip install scapy
```

3. **Windows users**: Install [Npcap](https://nmap.org/npcap/) for packet capture functionality

## Usage

Run the program with administrator privileges:

```bash
# Windows (run as Administrator)
python network_monitor.py

# Linux/macOS (run as root)
sudo python network_monitor.py
```

### Program Flow

1. **Dependency Check**: The program automatically checks if Scapy is installed and packet capture is working
2. **Action Selection**: Choose between packet sniffing or clearing logs
3. **Configuration**: If sniffing, configure:
   - Number of packets to capture (1-1000)
   - Filter type (0-17 options)
   - Output format (PCAP, text, or both)

### Available Filters

| Filter # | Description | BPF Filter |
|----------|-------------|------------|
| 0 | No filter | - |
| 1 | HTTP traffic | `tcp port 80` |
| 2 | TCP packets | `tcp` |
| 3 | UDP packets | `udp` |
| 4 | ICMP packets | `icmp` |
| 5 | DNS traffic | `port 53` |
| 6 | ARP packets | `arp` |
| 7 | Port 80 traffic | `port 80` |
| 8 | HTTPS traffic | `port 443` |
| 9 | DNS port traffic | `port 53` |
| 10 | SSH traffic | `port 22` |
| 11 | HTTP (TCP only) | `tcp and port 80` |
| 12 | DNS (UDP only) | `udp and port 53` |
| 13 | Non-TCP traffic | `not tcp` |
| 14 | Google DNS traffic | `host 8.8.8.8` |
| 15 | Local network | `net 192.168.1.0/24` |
| 16 | Broadcast packets | `broadcast` |
| 17 | Multicast packets | `multicast` |

### Output Formats

1. **PCAP files**: Binary format compatible with Wireshark and other network analysis tools
   - Unfiltered: `logs/captured_packets.pcap`
   - Filtered: `logs/captured_packets_filtered.pcap`

2. **Text logs**: Human-readable packet summaries
   - Unfiltered: `logs/net_monitor.log`
   - Filtered: `logs/filtered.log`

## File Structure

```
network-monitor/
├── network_monitor.py    # Main program file
├── logs/                 # Created automatically
│   ├── net_monitor.log
│   ├── filtered.log
│   ├── captured_packets.pcap
│   └── captured_packets_filtered.pcap
└── README.md
```

## Examples

### Example 1: Capture HTTP Traffic
```
Enter the count of packets (1-1000): 50
Enter the keynumber of your filter: 1
Specify logs format: 3
```
This captures 50 HTTP packets and saves them in both PCAP and text format.

### Example 2: Monitor Local Network
```
Enter the count of packets (1-1000): 100
Enter the keynumber of your filter: 15
Specify logs format: 1
```
This captures 100 packets from local network (192.168.1.0/24) and saves as PCAP only.

## Troubleshooting

### Common Issues

**"Packet capture error: [Errno 1] Operation not permitted"**
- Solution: Run the program with administrator/root privileges

**"Error: Scapy is not installed"**
- Solution: Install Scapy using `pip install scapy`

**"Possible causes: no npcap, no administrator rights"**
- Windows: Install Npcap from https://nmap.org/npcap/
- Linux/macOS: Install libpcap or run with sudo

### Permissions

This tool requires elevated privileges because:
- Network packet capture requires raw socket access
- Raw sockets are restricted to administrator/root users for security reasons

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for educational and authorized network analysis purposes only. Users are responsible for complying with applicable laws and regulations. Unauthorized network monitoring may be illegal in your jurisdiction.

## Author

Created by Mykola Maloied - feel free to contact me for questions or suggestions!