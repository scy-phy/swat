__author__ = 'bernardyuan'

import scapy
from scapy import all
from scapy import layers
import protocol

a = all.rdpcap('DLR/dlr.pcap')

a[0].show()
