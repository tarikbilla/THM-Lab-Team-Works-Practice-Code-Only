import os
import scapy.all as scapy

response = os.popen("ip route").read()
gateway_ip = response.split()[2]
print(gateway_ip)

network_ip = "172.24.41.0/24"
arp_request = scapy.ARP(pdst=network_ip)
#Creating Ethernet Broadcast Frame
broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
# combined Ethernet frame 
answered_list = scapy.srp(broadcast/arp_request, timeout=1, verbose=False)[0]
#element[1] refers to the response packet.
#lement[1].psrc retrieves the source IP address
allips = [element[1].psrc for element in answered_list]



for ip in allips:
    print(ip)

