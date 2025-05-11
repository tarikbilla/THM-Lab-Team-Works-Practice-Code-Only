import os
import scapy.all as scapy
def get_default_getway():
    response = os.popen("ip route").read()
    gateway_ip = response.split()[2]
    return gateway_ip


if __name__ == "__main__":
    getway = get_default_getway()
    print(getway)

