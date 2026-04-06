import socket
import json
import platform
import getpass

SERVER_HOST = "127.0.0.1"
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

    sock.send(json.dumps(data).encode())

    res = sock.recv(100000).decode()

    print("\n===== RESULT =====\n")
    print(res)

    sock.close()


if __name__ == "__main__":
    domains = input("Enter domains: ").split()

    for d in domains:
        send(d)
