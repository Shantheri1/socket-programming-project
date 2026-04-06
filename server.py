import socket #for talking between 2 computers
import threading #for handling multiple users simultaneously
import json
import time

HOST = '0.0.0.0' #accepts connections from any IP address
PORT = 5000


def subdomain_scan(domain):
    subs = ["www", "api", "mail", "admin"]
    results = []

    for s in subs:
        try:
            full = f"{s}.{domain}" #combines subdomain + domain
            ip = socket.gethostbyname(full) #converts domain name to ip address
            results.append({full: ip}) #stores full domain name with ip address
        except:
            pass #if subdomain does not exist just ignore it

    return results


def scan_port(domain, port): #checks if a port is open or not
    try:
        start = time.time()

        sock = socket.socket() #creates socket
        sock.settimeout(3)
        sock.connect((domain, port)) #connect domain and port   

        end = time.time()
        sock.close()

        return {
            "port": port,
            "status": "open",
            "time_ms": round((end - start) * 1000, 2)
        }

    except:
        return {"port": port, "status": "closed"}


#  NEW: Extract real server name + version
def get_server_info(domain):
    try:
        sock = socket.socket()
        sock.settimeout(3)
        sock.connect((domain, 80))

        req = f"GET / HTTP/1.1\r\nHost: {domain}\r\n\r\n"
        sock.send(req.encode())

        res = sock.recv(4096).decode(errors="ignore") #4096 is no of bytes to read like how much data you recieve at once
        sock.close()

        server_line = None
        for line in res.split("\r\n"):
            if line.lower().startswith("server:"):
                server_line = line.split(":", 1)[1].strip() # it splits like this ["Server", " nginx/1.18"] and then bcs of [1] takes 2nd part 
                #strip removes spaces
                break

        if server_line:
            parts = server_line.split("/") #splits server name and version
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
    #these headers are for security protections
#HSTS → HTTPS enforcement and prevents downgrade attacks
#CSP → prevent attacks and hacking via JS injection
#X-Frame → clickjacking protection
#X-Content → MIME protection

    except:
        return "Error"


def get_ssl_info(domain):
    import ssl
    import socket

    try:
        context = ssl.create_default_context() #creates secure connection setup

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock: #wrap_socket->adds encryption(Https) converts normal socket to secure ssl socket
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


#  UPDATED full_scan
def full_scan(domain):
    result = {}

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

    result["progress"] = "Scan completed"

    return result


def handle_client(conn, addr): # runs when someone connects
    print("\n========================")
    print(" NEW CLIENT CONNECTED ")
    print("========================")

    try:
        data = conn.recv(4096).decode()
        req = json.loads(data) #converts json to python dictionary

        client = req["client"]

        print(f"IP        : {addr[0]}")
        print(f"Hostname  : {client['hostname']}")
        print(f"User      : {client['user']}")
        print(f"OS        : {client['os']}")
        print("========================\n")

        domain = req["domain"]
        result = full_scan(domain)

        conn.send(json.dumps(result, indent=2).encode())#converts python dictionary to json string and indent=2 makes it pretty by indenting bw them and then encodes and sends
#and send result to client
    except Exception as e:
        conn.send(f"Error: {str(e)}".encode())

    conn.close()
    print("Client disconnected\n")


def start():
    server = socket.socket()
    server.bind((HOST, PORT)) #attach host+port
    server.listen(5) #max 5 user in queue not only 5 users
    print(f"[+] Server running on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
    start()

