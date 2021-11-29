from scapy.packet import Packet
from scapy.layers.inet import TCP, IP, Ether, ICMP

def process_pkt_private(pkt: Packet):
    if pkt.sniffed_on == PRIVATE_IFACE:
        print("received private pkt", pkt.sniffed_on, pkt.summary())
        if ICMP in pkt:
            # Create a new IP packet with specified src and dst
            newPort = (rand()%3000) - 1000
            
            srcIp = get_if_addr(conf.iface)  # default interface
            srcIp = get_if_addr("eth0")
            
            routIP = conf.route.route("0.0.0.0")[2]
            
            s=socket.socket()
            s.connect((ip,newPort))
            
            new_pkt = IP(src = routIp, dst="172.16.20.100") / pkt[ICMP]
            # Send the new packet over the public interface
            send(new_pkt, iface=PUBLIC_IFACE, verbose=False)
            
#ping[172.16.20.100] tests client 1 and 2

  
