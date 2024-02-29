import os
import socket
import threading
import sys

class PortScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.open_ports = []

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target_ip, port))
            if result == 0:
                print(f"\033[32m[+] Port {port}: Open\033[0m")
                self.open_ports.append(port)
            sock.close()
        except Exception as e:
            pass

    def scan_ports(self, start_port, end_port):
        print(f"\033[36m[*] Scanning ports {start_port}-{end_port} on {self.target_ip}\033[0m")
        for port in range(start_port, end_port + 1):
            threading.Thread(target=self.scan_port, args=(port,)).start()

def save_to_file(target_ip, open_ports):
    try:
        directory = "lookups"
        if not os.path.exists(directory):
            os.makedirs(directory)
        filename = os.path.join(directory, f"{target_ip}.txt")
        with open(filename, "w") as f:
            f.write(f"Target IP: {target_ip}\n")
            f.write("Open ports:\n")
            for port in open_ports:
                f.write(f"{port}\n")
        print(f"\033[36m[+] Results saved to {filename}\033[0m")
    except Exception as e:
        print(f"\033[31m[-] Error saving results: {e}\033[0m")

def main():
    try:
        print("\033[1;33m")
        print("█▀█ █▀█ █▀█ ▀█▀ █▀ █▀▀ ▄▀█ █▄░█")
        print("█▀▀ █▄█ █▀▄ ░█░ ▄█ █▄▄ █▀█ █░▀█")
        print("\033[0m")

        target_ip = input("\033[1mEnter the target IP address: \033[0m")
        start_port = int(input("\033[1mEnter the starting port: \033[0m"))
        end_port = int(input("\033[1mEnter the ending port: \033[0m"))

        if not (0 <= start_port <= 65535) or not (0 <= end_port <= 65535) or end_port < start_port:
            print("\033[31mInvalid port range.\033[0m")
            sys.exit(1)

        scanner = PortScanner(target_ip)
        scanner.scan_ports(start_port, end_port)
        save_to_file(target_ip, scanner.open_ports)
    except KeyboardInterrupt:
        print("\n\033[33mScan interrupted.\033[0m")
        sys.exit(1)
    except Exception as e:
        print(f"\033[31mError: {e}\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    main()
