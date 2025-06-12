from concurrent.futures import ThreadPoolExecutor


import getDefaultGateway
import allIP
import findMacAddress
import findVendor
import getPorts
import getOS
import getTTL
import getDeviceType

def scan_single_ip(ip):

    print(f"Scanning IP Address: {ip}")
    mac = findMacAddress.get_mac(ip).upper()
    print(f"MAC Address: {mac}")

    ttl = getTTL.get_ttl(ip)
    print(f"TTL: {ttl}")

    vendor = findVendor.get_vendor(mac)
    print(f"Vendor: {vendor}")

    os = getOS.detect_os(ip)
    print(f"{os}")

    ports = getPorts.scan_ports(ip)
    print(f"Open Ports: {ports}")
    # getPorts.scan_port_withServices(ip)
    
    dtype = getDeviceType.guess_type(vendor, ports)
    print(f"Device Type: {dtype}")

    
def main():
    defaultGateway = getDefaultGateway.get_default_getway();
    print(f"Default Gateway: " + defaultGateway+"\n");

    gateway_formate = defaultGateway + "/24"
    ips = allIP.scan_network(gateway_formate)

    print("All Connected IPs:")
    for ip in ips:
        print(ip)

    for ip in ips:
        print(f"\n")
        scan_single_ip(ip)


if __name__ == "__main__":

    main();

    # ip = input("Enter IP address: ").strip()
    # print("Start Scanning.....\n")
    # scan_single_ip(ip);