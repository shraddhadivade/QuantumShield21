"""
QuantumShield Messenger - Master Full-System Launcher.
Initializes SQLite WAL database, seeds post-quantum key pairs, mounts API + Frontend,
and boots the unified FastAPI ASGI server with intelligent auto-port detection.
"""
import sys
import os
import time
import socket
import webbrowser
import threading

# 1. Force Working Directory and Python Path to Project Root
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import uvicorn
from backend.database import init_db
from backend.auth import seed_default_users
from backend.app import app


def find_free_port(preferred_port=8000):
    """Checks preferred port and falls back to alternate ports if occupied."""
    candidate_ports = [preferred_port, 8001, 8080, 8888, 5000, 5500]
    for port in candidate_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return preferred_port


def open_browser(port):
    time.sleep(1.2)
    url = f"http://127.0.0.1:{port}/"
    print(f"\n[LAUNCHER] Opening QuantumShield in browser: {url}")
    try:
        webbrowser.open(url)
    except Exception:
        pass


def main():
    print("=" * 65)
    print("   QUANTUMSHIELD MESSENGER - POST-QUANTUM SECURE PLATFORM")
    print("   Powered by ML-KEM-768 | HKDF-SHA256 | AES-256-GCM | Ed25519")
    print("=" * 65)

    print("\n[*] Step 1: Initializing SQLite WAL Database...")
    init_db()

    print("[*] Step 2: Seeding Quantum Identities (Nova, Orion, Alice, Eve)...")
    seed_default_users()

    port = find_free_port(8000)

    print(f"\n[*] Step 3: Starting FastAPI + Frontend on http://127.0.0.1:{port}/")
    print(f"    - Main Application:   http://127.0.0.1:{port}/")
    print(f"    - Interactive Docs:   http://127.0.0.1:{port}/docs")
    print(f"    - Cryptographic API:  http://127.0.0.1:{port}/api/crypto/\n")
    print("[SERVER RUNNING] Keep this terminal open! Press Ctrl+C to stop.\n")

    threading.Thread(target=open_browser, args=(port,), daemon=True).start()

    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
