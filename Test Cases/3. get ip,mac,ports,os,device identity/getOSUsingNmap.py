import subprocess

def get_os_from_ip(ip):
    try:
        result = subprocess.run(['nmap', '-O', ip], capture_output=True, text=True)

        if result.returncode == 0:
            if 'OS details' in result.stdout:
                print(result.stdout.split('OS details')[1].strip())
            else:
                print(f"Unknown OS")
        else:
            print(f"{result.stderr}")

    except Exception as e:
        print(f"Error occurred: {e}")


ipAddress = input("Enter Ip Address: ");
get_os_from_ip(ipAddress)

