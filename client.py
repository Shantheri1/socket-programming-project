import socket
import json
import platform
import getpass
import time

SERVER_HOST = "10.30.200.167"
SERVER_PORT = 5000


def get_client_info():
    return {
        "hostname": socket.gethostname(),
        "ip": socket.gethostbyname(socket.gethostname()),
        "os": platform.system() + " " + platform.release(),
        "user": getpass.getuser()
    }


def send(domain):
    sock = socket.socket()
    sock.connect((SERVER_HOST, SERVER_PORT))

    data = {
        "domain": domain,
        "client": get_client_info()
    }

    request_start = time.time()  # start timing before sending

    sock.send(json.dumps(data).encode())

    res = sock.recv(100000).decode()

    request_end = time.time()  # stop timing after full response received

    sock.close()

    # --- Latency & Throughput (client-side view) ---
    latency_ms = round((request_end - request_start) * 1000, 2)  # round-trip time in ms
    response_bytes = len(res.encode())                            # size of data received
    duration_sec = (request_end - request_start)
    throughput_bps = round(response_bytes / duration_sec, 2) if duration_sec > 0 else 0

    print("\n===== RESULT =====\n")
    print(res)

    print("\n===== CLIENT-SIDE PERFORMANCE =====")
    print(f"  Domain          : {domain}")
    print(f"  Latency (RTT)   : {latency_ms} ms")
    print(f"  Data Received   : {response_bytes} bytes")
    print(f"  Throughput      : {round(throughput_bps / 1024, 2)} KB/s")
    print("====================================\n")


if __name__ == "__main__":
    domains = input("Enter domains: ").split()

    for d in domains:
        send(d)
