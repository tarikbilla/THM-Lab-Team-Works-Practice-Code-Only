# Get the default gateway IP
gateway=$(ip route | grep default | awk '{print $3}')
#gateway="172.24.41.0"   
echo "Default Gateway: $gateway"

# Extract the network part of the gateway
network_prefix=$(echo $gateway | cut -d'.' -f1-2)

# Loop (.1 to .254)
for i in {1..254}; do
    for j in {1..254}; do
        ip="$network_prefix.$i.$j"
        ping -c 1 -w 1 $ip &> /dev/null && echo "$ip is active"
        #echo "Complete $ip"
    done
done

echo "done test case 1"


read -p "Enter an IP address to find its MAC address: " user_ip
mac=$(arp -n $user_ip | grep -o -E '([a-f0-9]{1,2}:){5}[a-f0-9]{1,2}')
echo "MAC Address for $user_ip: $mac"

echo "done test case 2"
