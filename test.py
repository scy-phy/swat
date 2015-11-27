__author__ = 'bernardyuan'

import scapy
from scapy import all
from scapy.layers import  l2
from scapy import layers
import protocol

a = all.rdpcap('DLR/dlr.pcap')

a[30467].show()
b = l2.Ether(**a[30467][l2.Ether].fields)/l2.Dot1Q(**a[30467][l2.Dot1Q].fields)/protocol.DLR(**a[30467][protocol.DLR].fields)
print b.explicit
print b.payload.explicit

b.explicit = 1
b.payload.explicit = 1

print "str:",str(b)
print "hexdump:",all.hexdump(b)
all.sendp(str(b),iface='lo0')
