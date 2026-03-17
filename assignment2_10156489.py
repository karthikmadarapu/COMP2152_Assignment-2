"""
Author: <Karthik Madarapu>
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime


print("Python Version:", platform.python_version())
print("Operating System:", os.name)


# This dictionary maps common port numbers to their service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

class NetworkTool:
    def __init__(self, target):
        self.__target = target

   
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")

 # Q3: What is the benefit of using @property and @target.setter?
    # Using @property allows controlled access to private variables while still using simple syntax like an attribute.
    # The setter ensures validation logic is applied before modifying the value.
    # This prevents invalid data (like empty strings) from being assigned to the target.


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool, so it reuses the target attribute and its getter/setter methods.
# Instead of redefining target handling, it calls super().__init__(target) to initialize it.
# This avoids code duplication and keeps the structure clean and reusable.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
       
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))

            status = "Open" if result == 0 else "Closed"
            service = common_ports.get(port, "Unknown")

            self.lock.acquire()
            self.scan_results.append((port, status, service))
            self.lock.release()

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")

        finally:
            sock.close()

    def get_open_ports(self):
        return [r for r in self.scan_results if r[1] == "Open"]
    

# # Q4: What would happen without try-except here?
        # Without try-except, any network error (like unreachable host) would crash the program.
        # The scanner would stop execution instead of continuing with other ports.
        # Try-except ensures the program continues even if one port fails.
 # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows multiple ports to be scanned simultaneously, making the process much faster.
    # Without threading, scanning 1024 ports sequentially would take a long time (seconds per port).
    # Using threads reduces total scan time significantly.
    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )
        """)

        for port, status, service in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now()))
            )

        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        print("Database error:", e)


def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()

        for row in rows:
            print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")

        conn.close()

    except sqlite3.Error:
        print("No past scans found.")

# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    try:
        target = input("Enter target IP (default 127.0.0.1): ") or "127.0.0.1"

        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))

        if not (1 <= start_port <= 1024 and 1 <= end_port <= 1024):
            print("Port must be between 1 and 1024.")
            exit()

        if end_port < start_port:
            print("End port must be greater than or equal to start port.")
            exit()

    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        exit()

    scanner = PortScanner(target)

    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()

    print(f"\n--- Scan Results for {target} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: {status} ({service})")

    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, scanner.scan_results)

    choice = input("Would you like to see past scan history? (yes/no): ")
    if choice.lower() == "yes":
        load_past_scans()


# Q5: New Feature Proposal
# I would add a feature that filters only common service ports using a list comprehension.
# This would allow users to quickly identify important services like HTTP or SSH.
# The feature would use a list comprehension to filter results based on service names.
# Diagram: See diagram_studentID.png in the repository root


