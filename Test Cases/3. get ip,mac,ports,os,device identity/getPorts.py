import socket

def get_service(port):
    try:
        return socket.getservbyport(port, 'tcp')
    except:
        return 'Unknown Port'

def scan_port(target_ip):
    print(f"Starting scan on {target_ip}...\n")
    print(f"{'PORT':<10} {'STATE':<10} SERVICE")

    for port in range(1, 65536):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.01)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                service = get_service(port)
                print(f"{port}/tcp".ljust(10), "open  ".ljust(10), service)
            sock.close()
        except:
            pass

    print("\nScan completed.")

# User input
target_ip = input("Enter IP address: ")
scan_port(target_ip)

