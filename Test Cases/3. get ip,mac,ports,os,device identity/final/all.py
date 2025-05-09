import getDefaultGetway
import findMacAddress
import findVendor
import getPorts
import getOS
import getTTL
import getDeviceType

if __name__ == "__main__":
    ip = input("Enter IP address: ").strip()
    print("Start Scanning.....\n")

    print(f"IP Address: {ip}")
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
    
    dtype = getDeviceType.guess_type(vendor, ports, ttl)
    print(f"Device Type: {dtype}")
