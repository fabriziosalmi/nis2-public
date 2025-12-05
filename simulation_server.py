import http.server
import socketserver
import threading
import time

PORT = 8888

class MockHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/compliant':
            self.send_response(200)
            self.send_header('Strict-Transport-Security', 'max-age=63072000')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.end_headers()
            self.wfile.write(b"Compliant Response")
        elif self.path == '/non-compliant':
            self.send_response(200)
            # Missing headers
            self.end_headers()
            self.wfile.write(b"Non-Compliant Response")
        elif self.path == '/auth':
            auth_header = self.headers.get('Authorization')
            if auth_header == 'Bearer test-token':
                self.send_response(200)
                self.send_header('Strict-Transport-Security', 'max-age=63072000')
                self.end_headers()
                self.wfile.write(b"Authenticated")
            else:
                self.send_response(401)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass # Silence logs

def start_server():
    with socketserver.TCPServer(("", PORT), MockHandler) as httpd:
        print(f"Serving at port {PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    start_server()
