from scapy.sendrecv import send, sniff
def private_listener():
    print("sniffing packets on the private interface")
    sniff(prn=process_pkt_private, iface=PRIVATE_IFACE, filter="icmp or tcp")


import threading
def main():
    thread1 = threading.Thread(target=private_listener)
    thread2 = threading.Thread(target=public_listener)
    thread1.start()
    thread2.start()
    thread1.join()
    thread2.join()
    
from scapy.packet import Packet
from scapy.layers.inet import TCP, IP, Ether, ICMP
def process_pkt_private(pkt: Packet):
    if pkt.sniffed_on == PRIVATE_IFACE:
        print("received private pkt", pkt.sniffed_on, pkt.summary())
        if ICMP in pkt:
            # Create a new IP packet with specified src and dst
            new_pkt = IP(src="???", dst="???") / pkt[ICMP]
            # Send the new packet over the public interface
            send(new_pkt, iface=PUBLIC_IFACE, verbose=False)