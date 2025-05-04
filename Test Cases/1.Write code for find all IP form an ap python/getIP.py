import os
import scapy.all as scapy

def get_gateway_ip():
    response = os.popen("ip route | grep default").read()
    gateway_ip = response.split()[2]
    return gateway_ip

def scan_network(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered_list = scapy.srp(broadcast/arp_request, timeout=1, verbose=False)[0]
    
    devices_list = []
    for element in answered_list:
        device_info = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices_list.append(device_info)
    
    return devices_list

def display_devices(devices):
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

def main():
    gateway_ip = get_gateway_ip()
    network_ip = gateway_ip.rsplit('.', 1)[0] + '.1/24'
    devices = scan_network(network_ip)
    display_devices(devices)

if __name__ == "__main__":
    main()

