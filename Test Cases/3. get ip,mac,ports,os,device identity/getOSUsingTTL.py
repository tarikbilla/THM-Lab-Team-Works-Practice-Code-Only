import os

def getTTLData(ip):
    try:
        response = os.popen(f"ping -c 2 {ip}").read()
        if "ttl=" in response:
            ttl = int(response.split("ttl=")[1].split(" ")[0])
            return ttl
        return None
    except Exception as e:
        return None

def get_os(ip):
    ttl = getTTLData(ip)
    if ttl is None:
        return "Unable to get OS"
    elif ttl == 64:
        return "Likely Linux/Unix-based OS"
    elif ttl == 128:
        return "Likely Windows-based OS"
    elif ttl == 255:
        return "Cisco Routers/Solaris"
    else:
        return "Unknown OS"

ipAddress = input("Enter Ip Address: ");
getOS = get_os(ipAddress)
print("OS:", getOS)

