#!/usr/bin/env python3
from scapy.all import *
import argparse, time
from datetime import datetime

def packet_handler(packet):
	#protocol filtering
	if packet.haslayer(IP):
		print(f"{datetime.now()} - {packet[IP].src} -> {packet[IP].dst}")

def start_sniffing(interface, output_file):
	print(f"Starting packet capture on {interface} -> Saving to {output_file}")

	packets = sniff(
		iface=interface,
		prn=packet_handler,
		store=True,
		filter="tcp or udp",
		timeout=240
	)

	print("Capturing packets and saving")
	wrpcap(output_file, packets)

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-i", "--interface", required=True,  help="Interface")
	parser.add_argument("-o", "--output", required=True, help="Output PCAP file")
	args = parser.parse_args()
	start_sniffing(args.interface, args.output)
