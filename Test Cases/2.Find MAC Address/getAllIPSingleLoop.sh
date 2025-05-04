# Get the default gateway IP
#gateway=$(ip route | grep default | awk '{print $3}')
gateway="172.24.41.0"   # Change this to the desired gateway IP
echo "Default Gateway: $gateway"

# Extract the network part of the gateway 
network_prefix=$(echo $gateway | cut -d'.' -f1-3)
network="$network_prefix.0/24"


# Loop from .1 to .254
for i in {1..254}; do
    ip="$network_prefix.$i"
    # Ping each IP address and check if it is online or not 
    ping -c 1 -w 1 $ip &> /dev/null && echo "$ip is active"
done

echo "done test case 1"


# Allow user to input an IP and find its MAC address
read -p "Enter an IP address to find its MAC address: " user_ip
# Get and print the MAC address for the user's IP input
mac=$(arp -n $user_ip | grep -o -E '([a-f0-9]{1,2}:){5}[a-f0-9]{1,2}')
echo "MAC Address for $user_ip: $mac"

echo "done test case 2"
