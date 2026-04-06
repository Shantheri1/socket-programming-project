import socket
import ssl
import time
import re

PORTS = [80, 443, 21, 4433]

def scan(host, port):
  try:
   start = time.time()
   sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   sock.settimeout(3)

    # HTTPS or custom SSL server
    if port == 443 or port == 4433:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=host)

    sock.connect((host, port))

    # -------- HTTP / HTTPS --------
    if port == 80 or port == 443 or port == 4433:
       request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        sock.send(request.encode())

        response = sock.recv(4096).decode(errors="ignore")

        server = "Unknown"
        version = "Unknown"

        match = re.search(r"Server:\s*(.*)", response, re.IGNORECASE)
        if match:
            banner = match.group(1).strip()
            if "/" in banner:
                parts = banner.split("/")
                server = parts[0]
                version = parts[1].split()[0]
            else:
                server = banner

        http_version = "Unknown"
        match = re.search(r"(HTTP/\d\.\d)", response)
        if match:
            http_version = match.group(1)

        end = time.time()

        print("\n[HTTP/HTTPS]")
        print("Host:", host)
        print("Port:", port)
        print("Server:", server)
        print("Version:", version)
        print("HTTP Version:", http_version)
        print("Response Time:", round((end - start) * 1000, 2), "ms")

    # -------- FTP --------
    elif port == 21:

        banner = sock.recv(1024).decode(errors="ignore")

        end = time.time()

        print("\n[FTP]")
        print("Host:", host)
        print("Port:", port)
        print("Banner:", banner.strip())
        print("Response Time:", round((end - start) * 1000, 2), "ms")

    sock.close()

except:
    pass


# -------- MAIN --------

targets = input("Enter websites/IPs (space separated): ").split()

for target in targets:
target = target.strip()


print("\n==============================")
print("Scanning:", target)

for port in PORTS:
    scan(target, port)


print("\nScan Completed")
