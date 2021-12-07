#Brian Richey CS436
    #ping[172.16.20.100] tests client 1 and 2   
    
import threading
from scapy.packet import Packet
from scapy.sendrecv import send, sniff
from scapy.layers.inet import TCP, IP, Ether, ICMP

from random import seed
from random import randint

from socket import *


pvtIpMap = {} #dictionary key:client srcIp, val: dstIp 
pvtIcmpMap = {} #dictionary key:client srcId, val:client srcIp 
pubIpMap = {} #dictionary key:srcIp, val: dstIp 
clientIcmpIdPortMap = {} #dictionary key:client srcId, val: port number (randomly generated 2000-2250) 
clientTcpIpPortMap = {} #dictionary key:client srcIp, val: port number (randomly generated 2250-2500) 

routPvtIP = "10.0.0.2"
routPubIP = "172.16.20.2"

        
def process_pkt_private(pkt: Packet):
    if pkt.sniffed_on == PRIVATE_IFACE:
        print("received private pkt", pkt.sniffed_on, pkt.summary())
    
        if (IP in pkt and IP not in pvtIpMap):
            srcIp = pkt[IP].src  # gets source and destination ip/// ie. '0.0.0.0'
            dstIp = pkt[IP].dst
            pvtIpMap[str(srcIp)] = str(dstIp) #adds src and dst ips to dictionary 
            
        else: #already been mapped
            srcIp = pkt[IP].src #if in dictionary lookup dest IP
            dstIp = pvtIpMap[str(srcIp)] 
            
        if (ICMP in pkt and not in pvtIcmpMap) :
            # Create a new IP packet with specified src and dst
            
            srcId = pkt[icmp].id 
            srcIp = pkt[IP].src
            pvtIcmpMap[str(srcId)] = str(srcIp) #adds ICMP Id to ICMP private dictionary connecting ICMP id to src IP
           
            seed(1)
            newPort = randint(2000, 2250) #chooses port in 2000-2250 range
            clientIcmpIdPortMap[str(srcId)] = newPort #records clients port number via srcId key in dictionary
            s=socket.socket() #makes connection to new / hidden port
            s.connect((routIp,newPort))
            ss=StreamSocket(s,Raw)
           
            newIcmpPkt = IP(src = routPubIp, dst = pvtIpMap[str(srcIp)]) / pkt[ICMP] #src is now router dest via pvtIpMap
            
            # Send the new packet over the public interface
            send(newIcmpPkt, iface=PUBLIC_IFACE, verbose=False)
            
        elif(:
            newIcmpPkt = IP(src = routPubIp, dst = pvtIpMap[str(srcIp)]) / pkt[ICMP] #src is now router dest via pvtIpMap
            
            # Send the new packet over the public interface
            send(newIcmpPkt, iface=PUBLIC_IFACE, verbose=False)
            
        if (TCP in pkt and IP not in clientTcpIpPortMap):#TCP not mapped then create port connection and send
            
            seed(1)
            newPort = randint(2250, 2500) #chooses port in 2250-2500 range
            clientTcpIpPortMap[str(srcIp)] = newPort #records clients port number via srcIP key in dictionary
            
            s=socket.socket() #makes connection to new / hidden port
            s.connect((routIp,newPort))
            ss=StreamSocket(s,Raw)
            
            newTcpPkt = IP(src = routPubIp , dst = pvtIpMap[str(srcIp)])/TCP(dstPort = clientTcpIpPortMap[str(srcIp)]) #uses separate tables to gather address info
            send(newTcpPkt, iface = PUBLIC_IFACE, verbose=False) # sends new TCP pkt publicly
            
        else: #TCP mapped
            newTcpPkt = IP(src = routPubIp , dst = pvtIpMap[str(srcIp)])/TCP(dstPort = clientTcpIpPortMap[str(srcIp)]) #uses separate tables to gather address info
            send(newTcpPkt, iface = PUBLIC_IFACE, verbose=False) # sends new TCP pkt publicly
            

def process_pkt_public(pkt: Packet):
    if pkt.sniffed_on == PUBLIC_IFACE:
        print("received public pkt", pkt.sniffed_on, pkt.summary())
        if ICMP in pkt:
            # Create a new IP packet with specified src and dst
            new_pkt = IP(src="???", dst="???") / pkt[ICMP]
            # Send the new packet over the public interface
            send(new_pkt, iface=PRIVATE_IFACE, verbose=False)
            
        if TCP in pkt:


def private_listener():
    print("sniffing packets on the private interface")
    sniff(prn=process_pkt_private, iface=PRIVATE_IFACE, filter="icmp or tcp")

def public_listener():
    print("sniffing packets on the public interface")
    sniff(prn=process_pkt_public, iface=PUBLIC_IFACE, filter="icmp or tcp")

def main():
    thread1 = threading.Thread(target=private_listener)
    thread2 = threading.Thread(target=public_listener)
    print("starting multiple sniffing threads...")
    thread1.start()
    thread2.start()
    thread1.join()
    thread2.join()

main()
