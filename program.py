#Brian Richey CS436
    #ping[172.16.20.100] icmp tests client 1 and 2  
    #curl[172.16.20.100] TCP tests client 1 and 2  

import threading
from scapy.packet import Packet
from scapy.sendrecv import send, sniff
from scapy.layers.inet import TCP, IP, Ether, ICMP
from random import seed
from random import randint
from socket import *


pvtIpMap = {} #dictionary key:client srcIp, val:server dstIp 
pubIpMap = {} #dictionary key:server srcIp, val: client dstIp 
pvtIcmpMap = {} #dictionary key:client srcId, val:client srcIp 
pubIcmpMap = {} #dictionary key:server srcId, val:server srcIp 
clientTcpIpPortMap = {} #dictionary key:client srcIp, val: port number (randomly generated 2250-2500) 
serverTcpIpPortMap = {} #dictionary key:client srcIp, val: port number (randomly generated 2750-2999)

PRIVATE_IFACE = "eth0"
PUBLIC_IFACE = "eth1"
routPvtIP = "10.0.0.2"
routPubIP = "172.16.20.2"

def process_pkt_private(pkt: Packet):  
     if pkt.sniffed_on == PRIVATE_IFACE:
        print("received private pkt", pkt.sniffed_on, pkt.summary())
    
        if (IP in pkt and IP not in pvtIpMap):
            srcIp = pkt[IP].src  # gets source and destination ip/// ie. '0.0.0.0'
            dstIp = pkt[IP].dst
            pvtIpMap[str(srcIp)] = str(dstIp) #adds src and dst ips to dictionary 
            
        elif(IP in pkt and IP in pvtIpMap): #already been mapped
            srcIp = pkt[IP].src #if in dictionary lookup dest IP
            dstIp = pvtIpMap[str(srcIp)] 
        else: 
            pass
            
        if (ICMP in pkt and pkt[ICMP].id not in pvtIcmpMap) :
            # Create a new IP packet with specified src and dst
            
            srcId = pkt[ICMP].id 
            srcIp = pkt[IP].src
            pvtIcmpMap[str(srcIp)] = str(srcId) #adds ICMP Id to ICMP private dictionary connecting ICMP id to src IP
           
            newPubIcmpPkt = IP(src = routPubIP, dst = pvtIpMap[str(srcIp)]) / pkt[pvtIcmpMap[str(srcIp)]] #src is now router dest via pvtIpMap
            
            # Send the new packet over the public interface
            send(newIcmpPkt, iface=PUBLIC_IFACE, verbose=False)
            
        elif(ICMP in pkt and pkt[ICMP].id in pvtIcmpMap):
            newPubIcmpPkt = IP(src = routPubIP, dst = pvtIpMap[str(srcIp)]) / pkt[pvtIcmpMap[str(srcIp)]] #src is now router dest via pvtIpMap
            
            # Send the new packet over the public interface
            send(newPubIcmpPkt, iface=PUBLIC_IFACE, verbose=False)
        else: 
            pass
            
        if (TCP in pkt and IP not in clientTcpIpPortMap):#TCP not mapped then create port connection and send
            
            seed(1)
            newPort = randint(2250, 2500) #chooses port in 2250-2500 range
            clientTcpIpPortMap[str(srcIp)] = newPort #records clients port number via srcIP key in dictionary
            
            
            newPubTcpPkt = IP(src = routPubIP , dst = pvtIpMap[str(srcIp)])/TCP(clientTcpIpPortMap[str(srcIp)]) #uses separate tables to gather address info
            send(newPubTcpPkt, iface = PUBLIC_IFACE, verbose=False) # sends new TCP pkt publicly
            
        elif(TCP in pkt and IP in clientTcpIpPortMap): #TCP mapped
            newPubTcpPkt = IP(src = routPubIP , dst = pvtIpMap[str(srcIp)])/TCP(clientTcpIpPortMap[str(srcIp)]) #uses separate tables to gather address info
            send(newPubTcpPkt, iface = PUBLIC_IFACE, verbose=False) # sends new TCP pkt publicly
        else: 
            pass


def process_pkt_public(pkt: Packet):
    # same as before
    if pkt.sniffed_on == PUBLIC_IFACE:
        print("received public pkt", pkt.sniffed_on, pkt.summary())
        if (IP in pkt and IP not in pubIpMap):
            srcIp = pkt[IP].src  # gets source and destination ip/// ie. '0.0.0.0'
            dstIp = pkt[IP].dst
            pubIpMap[str(srcIp)] = str(dstIp) #adds src and dst ips to dictionary 
            
        elif(IP in pkt and IP in pubIpMap):
            srcIp = pkt[IP].src #if in dictionary lookup dest IP
            dstIp = pubIpMap[str(srcIp)] 
        else: 
            pass
            
        if (ICMP in pkt and pkt[ICMP].id not in pubIcmpMap):
            srcId = pkt[ICMP].id 
            srcIp = pkt[IP].src
            pubIcmpMap[str(srcId)] = str(srcIp) #adds ICMP Id to ICMP public dictionary connecting ICMP id to src IP
           
           
            newPvtIcmpPkt = IP(src = srcIp, dst = pubIpMap[str(srcIp)]) / pkt[pubIcmpMap[str(srcIp)]] #src is now router dest via pubIpMap
            
            # Send the new packet over the private interface
            send(newPvtIcmpPkt, iface=PRIVATE_IFACE, verbose=False)
            
        elif(ICMP in pkt and pkt[ICMP].id in pubIcmpMap):
            newPvtIcmpPkt = IP(src = srcIP, dst = pubIpMap[str(srcIp)]) / pkt[pubIcmpMap[str(srcIp)]] #src is now router dest via pubIpMap
            
            # Send the new packet over the private interface
            send(newPubIcmpPkt, iface=PRIVATE_IFACE, verbose=False)
        else: 
            pass
            
        if (TCP in pkt and IP not in serverTcpIpPortMap):
            seed(1)
            newPort = randint(2750, 2999) #chooses port in 2750-2999 range
            serverTcpIpPortMap[str(srcIp)] = newPort #records server's port number via srcIP key in dictionary
            
            
            newPvtTcpPkt = IP(src = srcIp , dst = pubIpMap[str(srcIp)])/TCP(serverTcpIpPortMap[str(srcIp)]) #uses separate tables to gather address info
            send(newPvtTcpPkt, iface = PRIVATE_IFACE, verbose=False) # sends new TCP pkt privately
            
        elif(TCP in pkt and IP in clientTcpIpPortMap): #TCP mapped
            newPvtTcpPkt = IP(src = srcIp , dst = pubIpMap[str(srcIp)])/TCP(serverTcpIpPortMap[str(srcIp)]) #uses separate tables to gather address info
            send(newPvtTcpPkt, iface = PRIVATE_IFACE, verbose=False) # sends new TCP pkt privately
        else: 
            pass

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
