# Basic Network Packet Sniffer

A command-line network packet sniffer developed in Python using
**Scapy** as part of a Cybersecurity Internship project.

The tool captures network packets in a controlled, authorized
environment, identifies common protocols, displays packet metadata,
maintains traffic statistics, and saves captured information to a CSV
file.

## Project Overview

-   **Project:** Basic Network Packet Sniffer
-   **Language:** Python 3
-   **Packet-capture library:** Scapy
-   **Test environment:** Kali Linux
-   **Interface:** Command-line (CLI)
-   **Output:** Terminal and CSV

This is an educational project for learning network traffic capture and
packet structure. It does not include a graphical user interface.

## Features

-   Capture IPv4 packets using Scapy.
-   Select a capture filter: `ALL`, `TCP`, `UDP`, or `ICMP`.
-   Choose the number of packets to capture.
-   Apply a 30-second timeout so capture does not wait indefinitely.
-   Display source and destination IP addresses.
-   Display source and destination ports for TCP and UDP packets.
-   Display packet size and timestamp.
-   Maintain TCP, UDP, ICMP, other, and total packet counts.
-   Save packet records and a capture summary to `packets.csv`.

## Requirements

-   Kali Linux or another Linux environment that supports packet capture
-   Python 3
-   Scapy
-   Authorization to capture traffic on the selected system or network

## Setup

Open a terminal in the project directory.

### 1. Create a virtual environment

``` bash
python3 -m venv venv
```

### 2. Activate it

``` bash
source venv/bin/activate
```

### 3. Install Scapy

``` bash
pip install scapy
```

If your virtual environment already exists and Scapy is installed, you
can skip these setup steps.

## Run the Project

From the project directory, run:

``` bash
sudo ./venv/bin/python sniffer.py
```

Packet capture may require elevated privileges. Use this tool only where
you have explicit authorization.

## How to Use

1.  Start the program with the command above.
2.  Select one of the displayed protocol options: `ALL`, `TCP`, `UDP`,
    or `ICMP`.
3.  Enter the number of packets you want to capture.
4.  Generate permitted network traffic during the capture if needed.
5.  The capture ends when the selected packet count is reached or the
    30-second timeout expires.
6.  Review packet details and final traffic statistics in the terminal.
7.  Open `packets.csv` to review the saved packet records and capture
    summary.

## Project Structure

``` text
network_sniffer/
├── sniffer.py       # Main Python program
├── packets.csv      # Captured packet records and summary
└── venv/            # Python virtual environment (created locally)
```

The `venv/` directory is generated on the local machine and generally
should not be uploaded to GitHub.

## CSV Output

The CSV log records packet information such as:

-   Packet number
-   Timestamp
-   Source IP
-   Destination IP
-   Protocol
-   Source port
-   Destination port
-   Packet size

The capture summary records the selected filter and the number of TCP,
UDP, ICMP, other, and total packets counted.

## Testing

The project was tested in Kali Linux using protocol-specific captures
and generated network traffic. Tests included:

-   General traffic capture using `ALL`
-   TCP packet capture
-   UDP packet capture
-   ICMP traffic generated with `ping`
-   Reviewing saved records with:

``` bash
cat packets.csv
```

The number of packets captured can vary depending on traffic available
during each test. A zero count for protocols outside the selected filter
is expected.

## Limitations

-   This is a basic educational sniffer, not a full packet-analysis
    platform.
-   The implementation focuses on IPv4 packet metadata and TCP, UDP, and
    ICMP identification.
-   It does not decrypt HTTPS or other encrypted application traffic.
-   The interface is command-line based.
-   Packet capture may require elevated privileges.
-   CSV logging is intended for basic review rather than large-scale
    packet storage.

## Possible Future Improvements

-   Add more detailed ARP and DNS analysis.
-   Add filtering by IP address and port.
-   Add network-interface selection.
-   Improve CSV reporting and log management.

## Ethical and Legal Use

Packet sniffing can expose sensitive network information. Run this
project only on your own systems or on networks where you have explicit
permission to capture traffic. Do not use it to monitor other people or
networks without authorization.

## Author

**Abdul Wasay**\
Cybersecurity Internship\
Project: Basic Network Packet Sniffer

------------------------------------------------------------------------

## Suggested `.gitignore`

``` gitignore
venv/
__pycache__/
*.pyc
```

Do not commit virtual-environment files. Review `packets.csv` before
publishing it and remove any sensitive IP addresses or traffic
information if necessary.
