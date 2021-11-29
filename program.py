

from scapy.packet import Packet
from scapy.layers.inet import TCP, IP, Ether, ICMP

def process_pkt_private(pkt: Packet):
    if pkt.sniffed_on == PRIVATE_IFACE:
        print("received private pkt", pkt.sniffed_on, pkt.summary())
        if ICMP in pkt:
            # Create a new IP packet with specified src and dst
            
            
            srcIp = get_if_addr(conf.iface)  # gets source ip/// ie. '0.0.0.0'
            srcIp = get_if_addr("eth0")
            
            routIP = conf.route.route("0.0.0.0")[2] #gets router ip///ie. '0.0.0.0'
            
            newPort = (rand()%3000) - 1000
            s=socket.socket() #makes connection to new / hidden port
            s.connect((srcIp,newPort))
            
            new_pkt = IP(src = routIp, dst="172.16.20.100") / pkt[ICMP]
            
            # Send the new packet over the public interface
            send(new_pkt, iface=PUBLIC_IFACE, verbose=False)
            
#ping[172.16.20.100] tests client 1 and 2

import threading
def main():
    thread1 = threading.Thread(target=private_listener)
    thread2 = threading.Thread(target=public_listener)
    thread1.start()
    thread2.start()
    thread1.join()
    thread2.join()

from scapy.sendrecv import send, sniff
def private_listener():
    print("sniffing packets on the private interface")
    sniff(prn=process_pkt_private, iface=PRIVATE_IFACE, filter="icmp or tcp")
