#!/bin/bash
#gateway=$(ip route | grep default | awk '{print $3}')
# Set a manual gateway IP
gateway="172.24.41.0"   # Change this to the desired gateway IP
echo "Default Gateway: $gateway"

# Extract the network part of the gateway
network_prefix=$(echo $gateway | cut -d'.' -f1-3)
network="$network_prefix.0/24"

# Using fping to check all IPs in parallel
echo "Scanning network: $network_prefix.0/24..."
fping -a -g $network_prefix.1 $network_prefix.254 2>/dev/null

echo "done!"

