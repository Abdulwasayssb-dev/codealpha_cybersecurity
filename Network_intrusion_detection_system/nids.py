#!/usr/bin/env python3
"""
Educational Network Intrusion Detection System (NIDS)
----------------------------------------------------
Monitors IP traffic on a selected network interface, applies basic
heuristic rules, and writes traffic and alert events to CSV files.

Use only on systems and networks you own or are authorized to monitor.
This educational tool is not a replacement for a production IDS such as
Suricata or Snort.
"""

import argparse
import csv
import sys
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    print(
        "Scapy is not installed. Install it with: "
        "sudo apt install python3-scapy",
        file=sys.stderr,
    )
    raise SystemExit(1)

BASE_DIR = Path(__file__).resolve().parent
TRAFFIC_FILE = BASE_DIR / "traffic_log.csv"
ALERT_FILE = BASE_DIR / "alerts.csv"
RESPONSE_FILE = BASE_DIR / "response_log.csv"

WINDOW_SECONDS = 10
PACKET_THRESHOLD = 100
SYN_THRESHOLD = 20
PORT_SCAN_THRESHOLD = 12
ALERT_COOLDOWN = 30

total_packets = 0
protocol_counts = defaultdict(int)
source_packets = defaultdict(deque)
source_syns = defaultdict(deque)
source_ports = defaultdict(deque)
last_alert = {}
alert_count = 0


def initialize_csv(path, headers):
    """Create a CSV file with headers if it does not exist or is empty."""
    if not path.exists() or path.stat().st_size == 0:
        with path.open("w", newline="", encoding="utf-8") as file:
            csv.writer(file).writerow(headers)


def create_log_files():
    """Create the traffic, alert, and response logs."""
    initialize_csv(
        TRAFFIC_FILE,
        [
            "Timestamp", "Source IP", "Destination IP", "Protocol",
            "Source Port", "Destination Port", "Packet Length",
        ],
    )
    initialize_csv(
        ALERT_FILE,
        ["Timestamp", "Severity", "Source IP", "Destination IP", "Reason"],
    )
    initialize_csv(
        RESPONSE_FILE,
        ["Timestamp", "Source IP", "Reason", "Recommended Action"],
    )


def append_csv(path, row):
    """Append one row to a CSV log."""
    with path.open("a", newline="", encoding="utf-8") as file:
        csv.writer(file).writerow(row)


def remove_old_entries(queue, now, window):
    """Remove events older than the rolling time window."""
    while queue and now - queue[0][0] > window:
        queue.popleft()


def generate_alert(src, dst, reason, severity="MEDIUM"):
    """Display and record an alert and a suggested administrator response."""
    global alert_count

    now = time.time()
    rule_name = reason.split(":")[0]
    alert_key = (src, rule_name)

    if now - last_alert.get(alert_key, 0) < ALERT_COOLDOWN:
        return

    last_alert[alert_key] = now
    alert_count += 1
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if "High traffic rate" in reason:
        action = "Review traffic volume and investigate the source"
    elif "High TCP SYN rate" in reason:
        action = "Review TCP connection attempts and verify legitimacy"
    elif "Possible port scan" in reason:
        action = "Review destination ports and verify authorization"
    else:
        action = "Investigate the event manually"

    print("\n" + "=" * 60)
    print(f"[{severity} ALERT] Suspicious network activity")
    print(f"Time: {timestamp}")
    print(f"Source IP: {src}")
    print(f"Destination IP: {dst}")
    print(f"Reason: {reason}")
    print(f"Recommended response: {action}")
    print("Status: Logged for administrator review")
    print("=" * 60)

    append_csv(ALERT_FILE, [timestamp, severity, src, dst, reason])
    append_csv(RESPONSE_FILE, [timestamp, src, reason, action])


def process_packet(packet):
    """Inspect one captured packet and apply basic heuristic rules."""
    global total_packets

    if IP not in packet:
        return

    now = time.time()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src = packet[IP].src
    dst = packet[IP].dst
    packet_length = len(packet)

    protocol = "OTHER"
    source_port = ""
    destination_port = ""

    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
    elif packet[IP].proto == 1:
        protocol = "ICMP"

    total_packets += 1
    protocol_counts[protocol] += 1

    append_csv(
        TRAFFIC_FILE,
        [
            timestamp, src, dst, protocol, source_port,
            destination_port, packet_length,
        ],
    )

    source_packets[src].append((now, dst))
    remove_old_entries(source_packets[src], now, WINDOW_SECONDS)

    if len(source_packets[src]) > PACKET_THRESHOLD:
        generate_alert(
            src,
            dst,
            f"High traffic rate: more than {PACKET_THRESHOLD} packets "
            f"in {WINDOW_SECONDS} seconds",
            "HIGH",
        )

    if TCP in packet:
        flags = int(packet[TCP].flags)

        # SYN set and ACK unset: a TCP connection initiation packet.
        if (flags & 0x02) and not (flags & 0x10):
            source_syns[src].append((now, destination_port))
            remove_old_entries(source_syns[src], now, WINDOW_SECONDS)

            if len(source_syns[src]) > SYN_THRESHOLD:
                generate_alert(
                    src,
                    dst,
                    f"High TCP SYN rate: more than {SYN_THRESHOLD} "
                    f"connection attempts in {WINDOW_SECONDS} seconds",
                    "HIGH",
                )

        if destination_port != "":
            source_ports[src].append((now, destination_port))
            remove_old_entries(source_ports[src], now, WINDOW_SECONDS)
            unique_ports = {port for _, port in source_ports[src]}

            if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                generate_alert(
                    src,
                    dst,
                    f"Possible port scan: traffic to {len(unique_ports)} "
                    f"distinct TCP ports in {WINDOW_SECONDS} seconds",
                    "HIGH",
                )


def show_summary():
    """Print session statistics when monitoring stops."""
    print("\n" + "=" * 50)
    print("             NIDS FINAL SUMMARY")
    print("=" * 50)
    print(f"Total IP packets observed: {total_packets}")
    print(f"Alerts generated: {alert_count}")
    print("\nProtocol statistics:")
    if protocol_counts:
        for protocol, count in sorted(protocol_counts.items()):
            print(f"  {protocol}: {count}")
    else:
        print("  No IP packets captured.")
    print(f"\nTraffic log:  {TRAFFIC_FILE}")
    print(f"Alert log:    {ALERT_FILE}")
    print(f"Response log: {RESPONSE_FILE}")
    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(
        description="Educational Network Intrusion Detection System"
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Interface to monitor, for example eth0 or wlan0. "
             "If omitted, Scapy selects its default interface.",
    )
    args = parser.parse_args()

    create_log_files()

    print("=" * 60)
    print("       NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 60)
    print(f"Interface: {args.interface or 'Scapy default interface'}")
    print("Rules: high packet rate, TCP SYN rate, possible TCP port scan")
    print("Logging: CSV traffic, alert, and response logs")
    print("Response: recommended actions only; no automatic blocking")
    print("Press Ctrl+C to stop monitoring.\n")

    try:
        sniff(
            iface=args.interface,
            prn=process_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
    except PermissionError:
        print(
            "Permission denied. On Kali Linux, try running with sudo.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    except OSError as error:
        print(f"Network capture error: {error}", file=sys.stderr)
        raise SystemExit(1)
    finally:
        show_summary()


if __name__ == "__main__":
    main()
