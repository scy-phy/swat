__author__ = 'bernardyuan'

from scapy import all
from scapy.layers import  l2
import protocol
# read the pcap file
a = all.rdpcap('DLR/dlr.pcap')
#in order: Beacon, nbr request, link status, locate fault,Announce, Sign on
# fake a packet and send through wireshark
for i in [0,12999,13763,12998,1937,30467]:
    a[i].show()

    #fabricate packet method 1:
    #construct from keywords
    b = l2.Ether(**a[i][l2.Ether].fields)/l2.Dot1Q(**a[i][l2.Dot1Q].fields)/protocol.DLR(**a[i][protocol.DLR].fields)
    # remember when constructed from keywords, do change the explicit value of ALL layers into 1
    # otherwise use method 2, given below:
    b.explicit = 1
    b.payload.explicit = 1

    # method 2:
    # construct from raw string
    # b0 = l2.Ether(**a[i][l2.Ether].fields)
    # b1 = l2.Dot1Q(**a[i][l2.Dot1Q].fields)
    # b2 = protocol.DLR(**a[i][protocol.DLR].fields)
    # b = l2.Ether(str(b0))/l2.Dot1Q(str(b1))/protocol.DLR(str(b2))

    # because the dynamic method used in fabricating DLR packet, the two lower layers' explicit value must be manually set 1

    print "str:",str(b)
    print "hexdump:",all.hexdump(b)
    all.sendp(str(b),iface='en0')
