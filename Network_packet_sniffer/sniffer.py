#!/usr/bin/env python3
"""
Basic Network Packet Sniffer
Terminal-only educational project using Scapy.

Use only on networks and devices you own or have explicit permission to monitor.
"""

import csv
import os
from datetime import datetime

from scapy.all import IP, TCP, UDP, ICMP, sniff

CSV_FILE = "packets.csv"
CAPTURE_TIMEOUT = 30


def get_packet_filter():
    """Ask the user which IPv4 traffic type to capture."""
    print("\nSelect packet type:")
    print("1. ALL")
    print("2. TCP")
    print("3. UDP")
    print("4. ICMP")

    choices = {
        "1": "ALL",
        "2": "TCP",
        "3": "UDP",
        "4": "ICMP",
    }

    while True:
        choice = input("Enter choice (1-4): ").strip()
        if choice in choices:
            return choices[choice]
        print("Invalid choice. Please enter 1, 2, 3, or 4.")


def packet_matches(packet, selected_filter):
    """Return True when a packet matches the selected protocol."""
    if IP not in packet:
        return False

    if selected_filter == "ALL":
        return True
    if selected_filter == "TCP":
        return TCP in packet
    if selected_filter == "UDP":
        return UDP in packet
    if selected_filter == "ICMP":
        return ICMP in packet

    return False


def get_packet_details(packet):
    """Extract the packet information displayed and saved to CSV."""
    ip_layer = packet[IP]

    protocol = "Other"
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
    elif ICMP in packet:
        protocol = "ICMP"

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": ip_layer.src,
        "destination_ip": ip_layer.dst,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "size": len(packet),
    }


def save_packet_to_csv(details):
    """Append one captured packet to packets.csv."""
    file_exists = os.path.isfile(CSV_FILE)

    with open(CSV_FILE, "a", newline="", encoding="utf-8") as csv_file:
        fieldnames = [
            "timestamp",
            "source_ip",
            "destination_ip",
            "protocol",
            "source_port",
            "destination_port",
            "size",
        ]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        if not file_exists or os.path.getsize(CSV_FILE) == 0:
            writer.writeheader()

        writer.writerow(details)


def main():
    print("=" * 55)
    print("             BASIC NETWORK PACKET SNIFFER")
    print("=" * 55)
    print("Educational use only — capture authorized traffic.")

    selected_filter = get_packet_filter()

    while True:
        try:
            packet_limit = int(input("\nHow many matching packets do you want to capture? "))
            if packet_limit > 0:
                break
            print("Please enter a number greater than zero.")
        except ValueError:
            print("Invalid input. Please enter a whole number.")

    protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
    captured_count = 0

    print("\nStarting capture...")
    print(f"Filter: {selected_filter}")
    print(f"Packet limit: {packet_limit}")
    print(f"Timeout: {CAPTURE_TIMEOUT} seconds")
    print("Press Ctrl+C to stop early.\n")

    def process_packet(packet):
        nonlocal captured_count

        if not packet_matches(packet, selected_filter):
            return

        details = get_packet_details(packet)
        captured_count += 1
        protocol_counts[details["protocol"]] += 1

        print("-" * 55)
        print(f"Packet Number : {captured_count}")
        print(f"Timestamp     : {details['timestamp']}")
        print(f"Source IP     : {details['source_ip']}")
        print(f"Destination IP: {details['destination_ip']}")
        print(f"Protocol      : {details['protocol']}")

        if details["protocol"] in ("TCP", "UDP"):
            print(f"Source Port   : {details['source_port']}")
            print(f"Destination Port: {details['destination_port']}")

        print(f"Packet Size   : {details['size']} bytes")

        save_packet_to_csv(details)

    def stop_after_limit(packet):
        # Stop once the requested number of matching packets has been processed.
        return captured_count >= packet_limit

    try:
        sniff(
            prn=process_packet,
            stop_filter=stop_after_limit,
            timeout=CAPTURE_TIMEOUT,
            store=False,
        )
    except PermissionError:
        print("\nPermission denied. Run the program with sudo on Kali Linux.")
        return
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except Exception as error:
        print(f"\nAn error occurred: {error}")
        return

    print("\n" + "=" * 55)
    print("                 CAPTURE SUMMARY")
    print("=" * 55)
    print(f"Selected Filter : {selected_filter}")
    print(f"Packets Captured: {captured_count}")
    print(f"TCP Packets     : {protocol_counts['TCP']}")
    print(f"UDP Packets     : {protocol_counts['UDP']}")
    print(f"ICMP Packets    : {protocol_counts['ICMP']}")
    print(f"Other IPv4      : {protocol_counts['Other']}")
    print(f"CSV File        : {CSV_FILE}")
    print("=" * 55)


if __name__ == "__main__":
    main()
