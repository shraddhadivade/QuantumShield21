"""
QuantumShield Frontend Server Launcher.
Starts a local HTTP server serving the QuantumShield frontend interface.
"""
import http.server
import socketserver
import os
import webbrowser
import sys

PORT = 5500
DIRECTORY = os.path.join(os.path.dirname(__file__), "frontend")

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

def start():
    os.chdir(DIRECTORY)
    print(f"================================================================")
    print(f"  QUANTUMSHIELD MESSENGER - FRONTEND DEVELOPMENT SERVER")
    print(f"================================================================")
    print(f"  Local URL: http://127.0.0.1:{PORT}/")
    print(f"  Serving Directory: {DIRECTORY}")
    print(f"  Press Ctrl+C to terminate the server.\n")

    try:
        with socketserver.TCPServer(("", PORT), Handler) as httpd:
            print(f"[ONLINE] Server successfully running at http://127.0.0.1:{PORT}/")
            httpd.serve_forever()
    except OSError as e:
        print(f"[INFO] Port {PORT} busy or already running. Trying port 5501...")
        with socketserver.TCPServer(("", 5501), Handler) as httpd:
            print(f"[ONLINE] Server running at http://127.0.0.1:5501/")
            httpd.serve_forever()

if __name__ == "__main__":
    start()
