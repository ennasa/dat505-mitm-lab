#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import datetime

class FakeWebServer(BaseHTTPRequestHandler):
	def do_GET(self):
		#log request
		client_ip = self.client_address[0]
		timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		print(f"Web {timestamp} - {client_ip} accessed {self.path}")
		with open("webserver_logs.txt", "a") as f:
			f.write(f"{timestamp} - {client_ip} - {self.path}\n")
		#send fake responses
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()

		response_html = f"""
		<html>
			<body>
				<h1>Fake Website</h1>
				<p>You have been redirected by DNS Spoofing!</p>
				<p>Request URL: {self.path}</p>
				<p>Client IP: {client_ip}</p>
				<p>Time: {timestamp}</p>
			</body>
		</html>
		"""
		self.wfile.write(response_html.encode())

	def log_message(self, format, *args):
		print(f"Web Access {format % args}")

if __name__ == "__main__":
	server = HTTPServer(('10.10.10.10', 80), FakeWebServer)
	print("Fake web server running")
	server.serve_forever()
