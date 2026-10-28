# Network Intrusion Detection System (NIDS)

An educational, Python-based Network Intrusion Detection System built
for Kali Linux. It captures IP packets using Scapy, applies simple
traffic heuristics, raises terminal alerts, and records packet, alert,
and recommended-response information in CSV files.

> **Authorized use only:** Monitor only devices and networks you own or
> have explicit permission to assess. This project is intended for
> learning and demonstration. It is not a replacement for a production
> IDS such as Suricata or Snort.

## Features

-   Live packet capture on a selected network interface
-   Basic protocol identification: TCP, UDP, ICMP, and other IP traffic
-   Heuristic alerts for:
    -   High packet rates from a source within a time window
    -   High TCP SYN rates
    -   TCP traffic to many distinct destination ports (possible port
        scanning)
-   CSV traffic, alert, and response logs
-   Terminal summary with packet and protocol counts
-   Recommended response guidance without automatically blocking
    addresses

## Project structure

``` text
NIDS-Project/
├── nids.py
├── README.md
├── traffic_log.csv       # created when the program runs
├── alerts.csv            # created when the program runs
└── response_log.csv      # created when the program runs
```

The CSV files are generated at runtime and may be excluded from Git if
they contain real network information.

## Requirements

-   Kali Linux or another Linux system
-   Python 3
-   Scapy
-   Root privileges or appropriate packet-capture permissions

## Installation on Kali Linux

Update package lists and install the required packages:

``` bash
sudo apt update
sudo apt install python3 python3-scapy tcpdump -y
```

Clone your repository or place `nids.py` in your project directory. Then
change into that directory:

``` bash
cd NIDS-Project
```

Check the Python syntax:

``` bash
python3 -m py_compile nids.py
```

## Identify your interface

``` bash
ip -br addr
ip route
```

Choose the interface that carries the traffic you are authorized to
monitor. Common names include `eth0`, `enp0s3`, and `wlan0`.

## Run the NIDS

For an interface named `eth0`:

``` bash
sudo python3 nids.py -i eth0
```

Replace `eth0` with your actual interface name. If no interface is
specified, Scapy uses its default interface:

``` bash
sudo python3 nids.py
```

Stop monitoring with `Ctrl+C`. The program prints a session summary.

## Logs

The program creates these CSV files beside `nids.py`:

-   **`traffic_log.csv`** --- timestamp, source and destination IP
    addresses, protocol, ports, and packet length
-   **`alerts.csv`** --- timestamp, severity, source and destination IP
    addresses, and detection reason
-   **`response_log.csv`** --- timestamp, source IP, detection reason,
    and recommended administrator action

Treat logs as potentially sensitive because they can reveal internal IP
addresses and network activity. Review them before committing them to a
public repository.

## Detection rules

Default demonstration thresholds are defined near the top of `nids.py`:

  --------------------------------------------------------------------------
  Setting                                      Default Purpose
  ----------------------- ---------------------------- ---------------------
  `WINDOW_SECONDS`                          10 seconds Rolling observation
                                                       window

  `PACKET_THRESHOLD`                               100 Alert when a source
                                                       exceeds this packet
                                                       count in the window

  `SYN_THRESHOLD`                                   20 Alert when a source
                                                       exceeds this SYN
                                                       count in the window

  `PORT_SCAN_THRESHOLD`                       12 ports Alert when TCP
                                                       traffic reaches at
                                                       least this many
                                                       distinct destination
                                                       ports in the window

  `ALERT_COOLDOWN`                          30 seconds Suppress repeated
                                                       alerts for the same
                                                       source and rule
                                                       category
  --------------------------------------------------------------------------

These are illustrative heuristics, not universal indicators of malicious
activity. Legitimate busy hosts can trigger alerts, and some attacks may
not trigger these rules. Tune the thresholds for your lab environment.

## Testing

1.  Start the program on the correct interface.

2.  In a second terminal, generate ordinary traffic on your own machine,
    for example:

    ``` bash
    ping -c 5 1.1.1.1
    ```

3.  Check the traffic log:

    ``` bash
    tail -n 10 traffic_log.csv
    ```

4.  Check alert and response logs:

    ``` bash
    cat alerts.csv
    cat response_log.csv
    ```

A ping test may not trigger an alert because ICMP traffic alone does not
necessarily exceed the detection thresholds. If no alert occurs, that is
expected behavior.

To troubleshoot capture visibility, compare with:

``` bash
sudo tcpdump -ni eth0 -c 10
```

If `tcpdump` sees packets but this program does not, verify the selected
interface and inspect any error message printed by the program.

## Response mechanism

The current response mechanism records a suggested administrator action
in `response_log.csv`. It does **not** automatically block traffic. This
conservative behavior helps avoid accidentally disconnecting the
monitored host or disrupting legitimate users.

## Limitations

-   Basic threshold-based detection; not signature-based detection
-   No automatic blocking or prevention
-   Captures only traffic visible to the chosen interface
-   Does not decrypt TLS or inspect encrypted application contents
-   Thresholds may produce false positives or miss suspicious activity
-   Not intended for production security monitoring

For a production-style lab extension, consider integrating Suricata or
Snort and testing their rule-based alerting in an isolated, authorized
environment.

## Responsible use

Use the software only on systems and networks you own or have explicit
permission to monitor. Do not publish logs containing sensitive
information, credentials, public IP details, or identifiable user
activity.

## Learning outcomes

-   Basic packet capture and network protocol analysis
-   Threshold-based anomaly detection
-   CSV event logging
-   Security alert handling and recommended response documentation
-   Testing and troubleshooting network monitoring on Kali Linux

## License

Choose a license before distributing this project. If you want others to
reuse and modify it, the MIT License is a common permissive option; add
a `LICENSE` file if you select it.
