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
serverTcpIpPortMap = {} #dictionary key:client srcIp, val: port number (randomly generated 2000-2249)

PRIVATE_IFACE = "eth0"
PUBLIC_IFACE = "eth1"
routPvtIP = "10.0.0.2"
routPubIP = "172.16.20.2"
ignoreIp = "129.114.26.193"

def process_pkt_private(pkt: Packet):  
    srcIp = pkt[IP].src  # gets source and destination ip/// ie. '0.0.0.0'
    dstIp = pkt[IP].dst
    if((srcIp != ignoreIp ) and (dstIp != ignoreIp) and (srcIp != routPubIP)):
        if pkt.sniffed_on == PRIVATE_IFACE:
            print("received private pkt", pkt.sniffed_on, pkt.summary())
    
            if (IP in pkt and IP not in pvtIpMap):
                srcIp = pkt[IP].src  # gets source and destination ip/// ie. '0.0.0.0'
                dstIp = pkt[IP].dst
                pvtIpMap[str(srcIp)] = str(dstIp) #adds src and dst ips to dictionary 
                pvtIpMap[str(dstIp)] = str(srcIp)

                pubIpMap[str(dstIp)] = routPubIP #fill pubIpMap
                pubIpMap[str(routPubIP)] = dstIp

            else:
                pass
                '''print("pvt pkt:")
                    pkt.show() '''
            
            if(IP in pkt and IP in pvtIpMap): #already been mapped
                srcIp = pkt[IP].src #if in dictionary lookup dest IP
                dstIp = pvtIpMap[str(srcIp)]
                '''print("pvt pkt:")
                pkt.show() ''' 
            else: 
                pass
            
            if (ICMP in pkt and pkt[ICMP].id not in pvtIcmpMap) : #not mapped
                # Create a new IP packet with specified src and dst
            
                srcId = pkt[ICMP].id 

                pvtIcmpMap[str(srcIp)] = srcId #adds ICMP Id to ICMP private dictionary connecting ICMP id to src IP
                pubIcmpMap[str(dstIp)] = srcId #adds ICMP Id to ICMP private dictionary connecting ICMP id to src IP

                if(srcIp != pubIpMap[routPubIP]):#src == client outgoing pvt pkt
                    newPubIcmpPkt = IP(src = routPubIP, dst = pvtIpMap[str(srcIp)]) / pkt[ICMP] #src is now router dest via pubIpMap
                    newPubIcmpPkt[ICMP].id = srcId #client id 
                    #print("new pub ICMP pkt:")
                    #newPubIcmpPkt.show()
                    # Send the new packet over the public interface
                    send(newPubIcmpPkt, iface=PUBLIC_IFACE, verbose=False)
                else:#src == server incoming pvt pkt
                    return

            if((ICMP in pkt) and (pkt[ICMP].id in pvtIcmpMap)): #previosuly mapped
                srcId = pkt[ICMP].id 
                
                if(srcIp != pubIpMap[routPubIP]):#src == client outgoing pub pkt
                    newPubIcmpPkt = IP(src = routPubIP, dst = pvtIpMap[str(srcIp)]) / pkt[ICMP] #src is now router dest via pubIpMap
                    newPubIcmpPkt[ICMP].id = srcId #client id 
                    #print("new pub ICMP pkt:")
                    #newPubIcmpPkt.show()
                    # Send the new packet over the public interface
                    send(newPubIcmpPkt, iface=PUBLIC_IFACE, verbose=False)
                else:#src == server pvt pkt
                    return
            
                
            if (TCP in pkt and IP not in clientTcpIpPortMap ):#TCP not mapped then create port connection and send
                
                clientnewPort = randint(2250, 2500) #chooses port in 2250-2500 range
                clientTcpIpPortMap[str(srcIp)] = str(clientnewPort) #records clients port number via srcIP key in dictionary
                
                servernewPort = randint(2000, 2249) #chooses port in 2000-2249 range
                serverTcpIpPortMap[str(dstIp)] = str(servernewPort) #records clients port number via srcIP key in dictionary
                
                if(srcIp != pubIpMap[routPubIP]):#src == client outgoing pub pkt 
                    TcpDst = pvtIpMap[str(srcIp)]
                    
                    TcpPort = serverTcpIpPortMap[str(dstIp)]

                    newPubTcpPkt = IP(src = routPubIP , dst = TcpDst)/ TCP(bytes(TcpPort,encoding='utf8')) #pkt[TCP] #uses separate tables to gather address info
                    #newPubTcpPkt[TCP].port = TcpPort
                    send(newPubTcpPkt, iface = PUBLIC_IFACE, verbose=False) # sends new TCP pkt publicly
                else:#src == server
                    return
            
            if(TCP in pkt and IP in clientTcpIpPortMap): #TCP mapped

                TcpDst = pvtIpMap[str(srcIp)]
                #print(TcpDst)
                TcpPort = serverTcpIpPortMap[str(dstIp)]
                #print(TcpPort)

                if(srcIp != pubIpMap[routPubIP]):#src == client outgoing pub pkt 
                    TcpDst = pvtIpMap[str(srcIp)]
                    
                    TcpPort = serverTcpIpPortMap[str(dstIp)]

                    newPubTcpPkt = IP(src = routPubIP , dst = TcpDst)/ TCP(bytes(TcpPort,encoding='utf8')) #pkt[TCP] #uses separate tables to gather address info
                    #newPubTcpPkt[TCP].port = TcpPort
                    send(newPubTcpPkt, iface = PUBLIC_IFACE, verbose=False) # sends new TCP pkt publicly
                else:#src == server
                    return
                
            else: 
                pass
        print("pvtIpMap:") 
        print(pvtIpMap)
        print("pubIpMap:") 
        print(pubIpMap)
        print("pvtIcmpMap:") 
        print(pvtIcmpMap)
        print("pubIcmpMap:")
        print(pubIcmpMap)
        print("clientTcpIpPortMap:") 
        print(clientTcpIpPortMap)
        print("serverTcpIpPortMap:") 
        print(serverTcpIpPortMap)
    else:
        return

def process_pkt_public(pkt: Packet):
    # same as before
    srcIp = pkt[IP].src  # gets source and destination ip/// ie. '0.0.0.0'
    dstIp = pkt[IP].dst
    if((srcIp != ignoreIp ) and (dstIp != ignoreIp) and (srcIp != routPubIP)):
        if pkt.sniffed_on == PUBLIC_IFACE:
            print("received public pkt", pkt.sniffed_on, pkt.summary())
            if (IP in pkt and IP not in pubIpMap):
                srcIp = pkt[IP].src  # gets source and destination ip/// ie. '0.0.0.0'
                dstIp = pkt[IP].dst
                pubIpMap[str(srcIp)] = str(dstIp) #adds src and dst ips to dictionary 
                pubIpMap[str(dstIp)] = str(srcIp)               
                
            
            if(IP in pkt and IP in pubIpMap):
                srcIp = pkt[IP].src #if in dictionary lookup dest IP
                dstIp = pubIpMap[str(srcIp)] 
                #print("pub pkt:")
                #pkt.show() 
            else: 
                pass
            
            if (ICMP in pkt and pkt[ICMP].id not in pubIcmpMap):
                srcId = pkt[ICMP].id 
                srcIp = pkt[IP].src
                pubIcmpMap[str(srcIp)] = srcId #adds ICMP Id to ICMP public dictionary connecting ICMP id to src IP
                pubIcmpMap[str(dstIp)] = srcId

                if (srcIp == pubIpMap[str(routPubIP)]):#src == server
                    IcmpDst = pvtIpMap[str(srcIp)]
                    newPvtIcmpPkt = IP(src = srcIp, dst = IcmpDst) / pkt[ICMP] #src is now router dest via pubIpMap
                    newPvtIcmpPkt[ICMP].id = pvtIcmpMap[IcmpDst]#**********
                    #print("new pvt ICMP pkt:")
                    #newPvtIcmpPkt.show()
                    # Send the new packet over the private interface
                    send(newPvtIcmpPkt, iface=PRIVATE_IFACE, verbose=False)
                else: #src == router
                    return
            
            if(ICMP in pkt and pkt[ICMP].id in pubIcmpMap):
                srcId = pkt[ICMP].id 
                srcIp = pkt[IP].src
            
                if (srcIP == pubIpMap[str(routPubIP)]):#src == server
                    IcmpDst = pvtIpMap[str(srcIp)]
                    newPvtIcmpPkt = IP(src = srcIp, dst = IcmpDst) / pkt[ICMP] #src is now router dest via pubIpMap
                    newPvtIcmpPkt[ICMP].id = pvtIcmpMap[IcmpDst]
                    # print("new pvt ICMP pkt:")
                    #newPvtIcmpPkt.show()
                    # Send the new packet over the private interface
                    send(newPvtIcmpPkt, iface=PRIVATE_IFACE, verbose=False)
                else: 
                    return
            
            if (TCP in pkt and IP not in serverTcpIpPortMap):
                srcIp = pkt[IP].src
                newPort = randint(2750, 2999) #chooses port in 2750-2999 range
                serverTcpIpPortMap[str(srcIp)] = str(newPort) #records server's port number via srcIP key in dictionary
                serverTcpIpPortMap[str(dstIp)] = str(newPort)
                #print(TcpPort)
                if (srcIp == pubIpMap[str(routPubIP)]):#src == server
                    TcpDst = pvtIpMap[str(srcIp)]
                    TcpPort = clientTcpIpPortMap[str(TcpDst)]
                    newPvtTcpPkt = IP(src = srcIp , dst = TcpDst)/ TCP(bytes(TcpPort,encoding='utf8'))#pkt[TCP] #uses separate tables to gather address info
                    #newPvtTcpPkt[TCP].port = TcpPort
                    # print("new pvt TCP pkt:")
                    #newPvtTcpPkt.show()
                    send(newPvtTcpPkt, iface = PRIVATE_IFACE, verbose=False) # sends new TCP pkt privately
                else: #src == router
                    return
            else:
                pass
            if(TCP in pkt and IP in serverTcpIpPortMap ): #TCP mapped
                
                if (srcIp == pubIpMap[str(routPubIP)]):#src == server
                    TcpDst = pvtIpMap[str(srcIp)]
                    TcpPort = clientTcpIpPortMap[str(TcpDst)]
                    newPvtTcpPkt = IP(src = srcIp , dst = TcpDst)/ TCP(bytes(TcpPort,encoding='utf8'))#pkt[TCP] #uses separate tables to gather address info
                    #newPvtTcpPkt[TCP].port = TcpPort
                    # print("new pvt TCP pkt:")
                    #newPvtTcpPkt.show()
                    send(newPvtTcpPkt, iface = PRIVATE_IFACE, verbose=False) # sends new TCP pkt privately
                else: #src == router
                    return
            else:
                pass
        print("pvtIpMap:") 
        print(pvtIpMap)
        print("pubIpMap:") 
        print(pubIpMap)
        print("pvtIcmpMap:") 
        print(pvtIcmpMap)
        print("pubIcmpMap:")
        print(pubIcmpMap)
        print("clientTcpIpPortMap:") 
        print(clientTcpIpPortMap)
        print("serverTcpIpPortMap:") 
        print(serverTcpIpPortMap)
    else:
        return

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
