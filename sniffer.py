from scapy.all import sniff, IFACES, IP, TCP, UDP, ICMP, DNSQR
from datetime import datetime

wifi_interface = IFACES.dev_from_index(13)

packet_count = 0


def analyze_packet(packet):
    global packet_count

    if not packet.haslayer(IP):
        return

    packet_count += 1
    ip = packet[IP]

    timestamp = datetime.now().strftime("%H:%M:%S")

    print(f"\n[{timestamp}] Packet #{packet_count}")
    print(f"Source IP:        {ip.src}")
    print(f"Destination IP:   {ip.dst}")

    if packet.haslayer(TCP):
        tcp = packet[TCP]

        print("Protocol:         TCP")
        print(f"Source Port:      {tcp.sport}")
        print(f"Destination Port: {tcp.dport}")
        print(f"TCP Flags:        {tcp.flags}")

    elif packet.haslayer(UDP):
        udp = packet[UDP]

        print("Protocol:         UDP")
        print(f"Source Port:      {udp.sport}")
        print(f"Destination Port: {udp.dport}")

    elif packet.haslayer(ICMP):
        print("Protocol:         ICMP")

    else:
        print(f"Protocol:         {ip.proto}")

    print(f"Packet Size:      {len(packet)} bytes")
    print("-" * 60)


def analyze_dns(packet):
    global packet_count

    if not packet.haslayer(IP):
        return

    if not packet.haslayer(DNSQR):
        return

    packet_count += 1

    ip = packet[IP]
    domain = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")

    timestamp = datetime.now().strftime("%H:%M:%S")

    print(f"\n[{timestamp}] DNS Query #{packet_count}")
    print(f"Source IP:        {ip.src}")
    print(f"DNS Server:       {ip.dst}")
    print(f"Domain:           {domain}")
    print("-" * 60)


def analyze_web(packet):
    global packet_count

    if not packet.haslayer(IP):
        return

    packet_count += 1

    ip = packet[IP]
    timestamp = datetime.now().strftime("%H:%M:%S")

    print(f"\n[{timestamp}] Web Traffic #{packet_count}")
    print(f"Source IP:        {ip.src}")
    print(f"Destination IP:   {ip.dst}")

    if packet.haslayer(TCP):
        tcp = packet[TCP]

        print("Protocol:         TCP")
        print(f"Source Port:      {tcp.sport}")
        print(f"Destination Port: {tcp.dport}")
        print(f"TCP Flags:        {tcp.flags}")

    elif packet.haslayer(UDP):
        udp = packet[UDP]

        print("Protocol:         UDP")
        print(f"Source Port:      {udp.sport}")
        print(f"Destination Port: {udp.dport}")

    print(f"Packet Size:      {len(packet)} bytes")
    print("-" * 60)


def start_all_traffic():
    global packet_count
    packet_count = 0

    print("\n" + "=" * 60)
    print("              ALL TRAFFIC MODE")
    print("=" * 60)
    print("Capturing network traffic...")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=wifi_interface,
            prn=analyze_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\n\nCapture stopped.")
        print(f"Total packets captured: {packet_count}")
        print("=" * 60)


def start_dns_sniffer():
    global packet_count
    packet_count = 0

    print("\n" + "=" * 60)
    print("               DNS TRAFFIC MODE")
    print("=" * 60)
    print("Monitoring DNS queries...")
    print("Open a website to generate DNS traffic.")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=wifi_interface,
            filter="udp port 53 or tcp port 53",
            prn=analyze_dns,
            store=False
        )

    except KeyboardInterrupt:
        print("\n\nDNS capture stopped.")
        print(f"DNS queries captured: {packet_count}")
        print("=" * 60)


def start_web_sniffer():
    global packet_count
    packet_count = 0

    print("\n" + "=" * 60)
    print("               WEB TRAFFIC MODE")
    print("=" * 60)
    print("Monitoring HTTPS and QUIC traffic...")
    print("Open a website to generate web traffic.")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=wifi_interface,
            filter="tcp port 443 or udp port 443",
            prn=analyze_web,
            store=False
        )

    except KeyboardInterrupt:
        print("\n\nWeb traffic capture stopped.")
        print(f"Web packets captured: {packet_count}")
        print("=" * 60)


print("=" * 60)
print("             BASIC NETWORK SNIFFER")
print("=" * 60)
print("\n1. All Traffic")
print("2. DNS Traffic")
print("3. Web Traffic")
print("4. Exit")

choice = input("\nSelect an option: ")

if choice == "1":
    start_all_traffic()

elif choice == "2":
    start_dns_sniffer()

elif choice == "3":
    start_web_sniffer()

elif choice == "4":
    print("Exiting...")

else:
    print("Invalid option.")