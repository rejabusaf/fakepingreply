
from scapy.all import *
import random

def ping_mod(pkt):
    if IP in pkt:
        dest = pkt[IP].dst
        sour = pkt[IP].src
        mdest = pkt[Ether].dst
        msour = pkt[Ether].src
        pkt[Ether].dst = msour
        pkt[Ether].src = mdest
        pkt[IP].dst = sour
        pkt[IP].src = dest
        pkt[IP].id = random.randint(1,2048)
        pkt[IP].ttl = pkt[IP].ttl - 3
        pkt[IP].chksum = None
        pkt[ICMP].type = 0
        pkt[ICMP].code = 0
        pkt[ICMP].chksum = None
        sendp(pkt)


sniff(filter="icmp[icmptype]==8 and icmp[icmpcode]==0", prn=ping_mod)

# Run the following on Lumension/Heat server to reply for the deprecated ping request:

#sniff(filter="icmp[icmptype]==8 and icmp[icmpcode]==37", prn=ping_mod)

