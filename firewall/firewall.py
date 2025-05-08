from scapy.all import sniff, IP, TCP, UDP#, get_if_list
import logging

#print(get_if_list())
#inter_face = input("Enter the interface you want to sniff: ")

# logging
logging.basicConfig(filename="firewall_log.txt", level=logging.INFO,
                    format="%(asctime)s - %(message)s")

# Define firewall rules
BLOCKED_IPS = ["192.168.1.10"]
BLOCKED_PORTS = [80, 443]

def packet_callback(packet):
    if IP in packet:  # Check if the packet has an IP layer
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Block packets from blocked IP addresses
        if src_ip in BLOCKED_IPS:
            logging.info(f"Blocked packet from IP: {src_ip}")
            return  # Drop the packet

        # Check for TCP/UDP protocols and filter based on destination ports
        if TCP in packet or UDP in packet:
            port = packet[TCP].dport if TCP in packet else packet[UDP].dport

            # Block packets to blocked ports
            if port in BLOCKED_PORTS:
                logging.info(f"Blocked packet to port {port} from IP: {src_ip}")
                return  # Drop the packet

        # If the packet passes the filters, log it as allowed
        logging.info(f"Allowed packet: {src_ip} -> {dst_ip}")

# Start sniffing packets
print("Firewall is running...")
sniff(filter="ip", prn=packet_callback, store=0, iface="Ethernet")  # Update iface to your active network interface name