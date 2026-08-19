"""Localhost test server for manual and automated testing."""
from http.server import BaseHTTPRequestHandler, HTTPServer
class TestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "Python-Test-Server")
        self.send_header("Server", "TestServer/1.0")
        self.send_header("Strict-Transport-Security", "max-age=86400")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Test Server</h1></body></html>")
    def log_message(self, format, *args): pass
if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8080), TestHandler)
    print("Starting test server on http://127.0.0.1:8080")
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    server.server_close()
