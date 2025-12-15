#!/usr/bin/env python3
"""
Capture the exact bytes python-oracledb sends for AUTH phase one.
"""
import socket
import struct

class PacketCapture:
    """Intercept and log packets."""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.packets_sent = []
        self.packets_received = []

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        print(f"Connected to {self.host}:{self.port}")

    def send(self, data):
        self.packets_sent.append(data)
        self.sock.sendall(data)

    def recv(self, size):
        data = self.sock.recv(size)
        self.packets_received.append(data)
        return data

    def recv_packet(self):
        """Receive a TNS packet."""
        header = self.sock.recv(8)
        if len(header) < 8:
            return None

        # Check if large SDU (4-byte length) or small (2-byte length)
        # In large SDU mode, length is first 4 bytes
        length = struct.unpack(">I", header[:4])[0]
        packet_type = header[4]

        remaining = length - 8
        body = b""
        while len(body) < remaining:
            chunk = self.sock.recv(remaining - len(body))
            if not chunk:
                break
            body += chunk

        return header + body

def hex_dump(data, prefix="  "):
    """Pretty print hex dump."""
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        print(f"{prefix}{i:04x}: {hex_str}")

def main():
    # Try to connect using python-oracledb thin mode
    try:
        import oracledb
    except ImportError:
        print("python-oracledb not installed. Install with: pip install oracledb")
        print("\nLet's manually trace the protocol flow instead...")
        return

    # Use thin mode (pure Python, no Oracle client needed)
    oracledb.init_oracle_client(lib_dir=None)

    print("Connecting to Oracle using python-oracledb...")
    try:
        conn = oracledb.connect(
            user="system",
            password="testpass",
            dsn="localhost:1521/FREEPDB1",
            mode=oracledb.DEFAULT_AUTH
        )
        print("Connected successfully!")
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM DUAL")
        print("Query result:", cursor.fetchone())
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Connection error: {e}")

if __name__ == "__main__":
    main()
