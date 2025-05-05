import socket

def scan_ports(target_ip):
    open_ports = []
    for port in range(1, 10000):  # or 65536 for full range
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.01)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass

    return open_ports



def get_service(port):
    try:
        return socket.getservbyport(port, 'tcp')
    except:
        return 'Unknown Port'

def scan_port_withServices(_target_ip):
    print(f"Starting scan on {target_ip}...\n")
    print(f"{'PORT':<10} {'STATE':<10} SERVICE")

    for port in range(1, 10000): #65536
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

if __name__ == "__main__":
    target_ip = input("Enter IP address: ")
    scan_port_withServices(target_ip)