from scapy.all import *
import csv
from collections import Counter

class TrafficParser:
	def __init__(self, pcap_file):
		self.packets = rdpcap(pcap_file)
		self.urls = []
		self.dns_queries = []
		self.protocol_counts = Counter()
		self.top_talkers = Counter()

	def extract_http_urls(self, packet):
		if packet.haslayer(TCP) and packet.haslayer(Raw):
			try:
				payload = packet[Raw].load.decode('utf-8', errors='ignore')

				if 'GET' in payload or 'POST' in payload:
					for line in payload.split('\n'):
						if line.startswith('GET') or line.startswit('POST'):
							self.urls.append(line.strip())
			except:
				pass

	def extract_dns_queries(self, packet):
		if packet.haslayer(DNSQR):
			dns = packet[DNSQR]
			self.dns_queries.appen(dns.qname.decode())

	def analyze_protocols(self, packet):
		if packet.haslayer(IP):
			src = packet[IP].src
			dst = packet[IP].dst
			self.top_talkers[src] += 1
			self.top_talkers[dst] += 1

			if packet.haslayer(ICMP): self.protocol_counts['ICMP'] += 1
			if packet.haslayer(TCP): self.protocol_counts['TCP'] += 1
			if packet.haslayer(UDP): self.protocol_counts['UDP'] += 1
			if packet.haslayer(ARP): self.protocol_counts['ARP'] += 1

			if packet.haslayer(TCP):
				if packet[TCP].dport == 80 or packet[TCP].sport == 80:
					self.protocol_counts['HTTP'] += 1
				elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
					self.protocol_counts['HTTP'] += 1
				elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                                        self.protocol_counts['HTTP'] += 1
				elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
                                        self.protocol_counts['HTTP'] += 1
			elif packet.haslayer(UDP):
                                if packet[UDP].dport == 53 or packet[UDP].sport == 53: self.protocol_counts['DNS'] += 1

	def parse_all(self):
		for packet in self.packets:
			self.analyze_protocols(packet)
			self.extract_dns_queries(packet)
			self.extract_http_urls(packet)

	def generate_reports(self):
		#save URLS
		with open('visited_urls.txt', 'w') as f:
			for url in set(self.urls):
				f.write(f"{url}\n")
		#save DNS queries
		with open('dns_queries.txt', 'w') as f:
			for query in set(self.dns_queries):
				f.write(f"{query}\n")
		#save protocol counts
		with open('protocol_counts.csv', 'w', newline='') as f:
			writer = csv.writer(f)
			writer.writerow(['Protocol', 'Count'])
			for protocol, count in self.protocol_counts.items():
				writer.writerow([protocol, count])
		#save top talkers
		with open('top_talkers.csv', 'w', newline='') as f:
			writer = csv.writer(f)
			writer.writerow(['IP Address', 'Packet Count'])
			for ip, count in self.top_talkers.most_common(10):
				writer.writerow([ip, count])
if __name__ == "__main__":
	import sys
	if len(sys.argv) != 2:
		sys.exit(1)
	pcap_file = sys.argv[1]
	parser = TrafficParser(pcap_file)
	parser.parse_all()
	parser.generate_reports()
