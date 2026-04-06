import socket
import threading
import json
import time

HOST = '0.0.0.0'
PORT = 5000


def subdomain_scan(domain):
    subs = ["www", "api", "mail", "admin"]
    results = []

    for s in subs:
        try:
            full = f"{s}.{domain}"
            ip = socket.gethostbyname(full)
            results.append({full: ip})
        except:
            pass

    return results


def scan_port(domain, port):
    try:
        start = time.time()

        sock = socket.socket()
        sock.settimeout(3)
        sock.connect((domain, port))

        end = time.time()
        sock.close()

        return {
            "port": port,
            "status": "open",
            "time_ms": round((end - start) * 1000, 2)
        }

    except:
        return {"port": port, "status": "closed"}


def get_server_info(domain):
    try:
        sock = socket.socket()
        sock.settimeout(3)
        sock.connect((domain, 80))

        req = f"GET / HTTP/1.1\r\nHost: {domain}\r\n\r\n"
        sock.send(req.encode())

        res = sock.recv(4096).decode(errors="ignore")
        sock.close()

        server_line = None
        for line in res.split("\r\n"):
            if line.lower().startswith("server:"):
                server_line = line.split(":", 1)[1].strip()
                break

        if server_line:
            parts = server_line.split("/")
            name = parts[0]
            version = parts[1] if len(parts) > 1 else "Unknown"
        else:
            name = "Unknown"
            version = "Unknown"

        return {
            "server_name": name,
            "server_version": version
        }

    except:
        return {
            "server_name": "Error",
            "server_version": "Error"
        }


def check_headers(domain):
    try:
        sock = socket.socket()
        sock.settimeout(3)
        sock.connect((domain, 80))

        req = f"GET / HTTP/1.1\r\nHost: {domain}\r\n\r\n"
        sock.send(req.encode())

        res = sock.recv(4096).decode(errors="ignore")
        sock.close()

        return {
            "HSTS": "Present" if "Strict-Transport-Security" in res else "Missing",
            "CSP": "Present" if "Content-Security-Policy" in res else "Missing",
            "X-Frame": "Present" if "X-Frame-Options" in res else "Missing",
            "X-Content": "Present" if "X-Content-Type-Options" in res else "Missing"
        }

    except:
        return "Error"


def get_ssl_info(domain):
    import ssl
    import socket

    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert['issuer'])
        valid_till = cert['notAfter']

        return {
            "Issuer": issuer.get("organizationName", "Unknown"),
            "Valid Till": valid_till
        }

    except Exception as e:
        return {
            "Issuer": "Error",
            "Valid Till": str(e)
        }


def full_scan(domain):
    result = {}

    scan_start = time.time()  # start timing the full scan

    # Step 0 → Server detection
    result["progress"] = "Detecting server..."
    server_info = get_server_info(domain)
    result.update(server_info)

    # Step 1
    result["progress"] = "Scanning subdomains..."
    result["subdomains"] = subdomain_scan(domain)

    # Step 2
    result["progress"] = "Scanning ports..."
    result["ports"] = [scan_port(domain, p) for p in [80, 443, 8080, 8443]]

    # Step 3
    result["progress"] = "Checking headers..."
    result["headers"] = check_headers(domain)

    # Step 4
    result["progress"] = "Fetching SSL info..."
    result["ssl"] = get_ssl_info(domain)

    scan_end = time.time()

    result["progress"] = "Scan completed"

    # --- Performance Metrics ---
    scan_duration_sec = round(scan_end - scan_start, 3)  # total scan time in seconds
    result_json = json.dumps(result, indent=2)
    response_bytes = len(result_json.encode())  # size of the response in bytes

    # Throughput = bytes sent / time taken (bytes per second)
    throughput_bps = round(response_bytes / scan_duration_sec, 2) if scan_duration_sec > 0 else 0

    result["performance"] = {
        "scan_duration_sec": scan_duration_sec,
        "response_size_bytes": response_bytes,
        "throughput_bytes_per_sec": throughput_bps,
        "throughput_kb_per_sec": round(throughput_bps / 1024, 2)
    }

    return result


def handle_client(conn, addr):
    print("\n========================")
    print(" NEW CLIENT CONNECTED ")
    print("========================")

    try:
        data = conn.recv(4096).decode()
        req = json.loads(data)

        client = req["client"]

        print(f"IP        : {addr[0]}")
        print(f"Hostname  : {client['hostname']}")
        print(f"User      : {client['user']}")
        print(f"OS        : {client['os']}")
        print("========================\n")

        domain = req["domain"]
        result = full_scan(domain)

        response_json = json.dumps(result, indent=2)
        conn.send(response_json.encode())

        # Print server-side performance summary
        perf = result.get("performance", {})
        print(f"[PERFORMANCE] Domain        : {domain}")
        print(f"[PERFORMANCE] Scan Duration : {perf.get('scan_duration_sec')} sec")
        print(f"[PERFORMANCE] Response Size : {perf.get('response_size_bytes')} bytes")
        print(f"[PERFORMANCE] Throughput    : {perf.get('throughput_kb_per_sec')} KB/s")

    except Exception as e:
        conn.send(f"Error: {str(e)}".encode())

    conn.close()
    print("Client disconnected\n")


def start():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # allows port reuse after restart
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[+] Server running on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
    start()
