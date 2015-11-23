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
from __future__ import print_function, division

import ctypes
import math
import signal
import sys
import threading

from scapy import all as scapy_all

import commons.util
import scaling
import swat

_pump1_in = 0
_pump = 0

_olevel = 1.004
_rlevel = 1.004
_elevel = 1.004

L = 0.05
tau = 1000
alpha = 0.002
cusum = 0

_flow = 2.5  # Water flow in m^3/h
DIA = 1.38  # Tank 1 diameter

_stop_sniffer = False
_is_first_pck = True


def get_model_parameters(packet):
    if swat.SWAT_P1_RIO_AI in packet:
        global _rlevel, _flow
        l = ctypes.c_short(packet[swat.SWAT_P1_RIO_AI].level)
        l = scaling.current_to_signal(l.value, scaling.P1Level)
        f = ctypes.c_short(packet[swat.SWAT_P1_RIO_AI].flow)
        _flow = scaling.current_to_signal(f.value, scaling.P1Flow)
        _rlevel = l * 0.001

    if swat.SWAT_P1_RIO_DI in packet:
        global _pump1_in, _pump
        _valve = packet[swat.SWAT_P1_RIO_DI].valve_open
        _pump = packet[swat.SWAT_P1_RIO_DI].pump1_run


def calculate_cusum():
    global _pump1_in, _pump, _rlevel, _elevel, cusum
    u = _flow / (3600 * math.pi * math.pow(DIA / 2, 2))  # Water volume change
    u *= _valve - _pump  # Direction of water volume change
    _elevel = _elevel + u + L * (_rlevel - _elevel)

    cusum += abs(_rlevel - _elevel) - alpha
    cusum = max(cusum, 0)

    print('{},{},{},{},{}'.format(_olevel, _rlevel, _elevel, abs(_rlevel - _elevel), cusum), end='')
    if cusum > tau:
        cusum = 0
        print(', SWaTAssault detected!!!!')
    else:
        print('')


def read_real_level(packet):
    if swat.SWAT_P1_RIO_AI in packet:
        l = ctypes.c_short(packet[swat.SWAT_P1_RIO_AI].level).value
        slevel = ctypes.c_short(packet[swat.SWAT_P1_RIO_AI].level)
        l = scaling.current_to_signal(slevel.value, scaling.P1Level)
        global _olevel, _elevel, _is_first_pck
        _olevel = l * 0.001
        if _is_first_pck:
            _elevel = _olevel
            _is_first_pck = False


def stop(p):
    global _stop_sniffer
    return _stop_sniffer


def start():
    __setup()
    try:
        # Thread to read real value before injection
        t_sniff_eth0 = threading.Thread(target=scapy_all.sniff,
                                        kwargs={'iface': 'eth0', 'store': 0,
                                                'prn': lambda p: read_real_level(p),
                                                'stop_filter': lambda p: stop(p)})

        # Thread to read model parameters after injection
        t_sniff_eth1 = threading.Thread(target=scapy_all.sniff,
                                        kwargs={'iface': 'eth1', 'store': 0,
                                                'prn': lambda p: get_model_parameters(p),
                                                'stop_filter': lambda p: stop(p)})

        t_detection = commons.util.RepeatEvery(1, calculate_cusum)
        print("*** Starting detection")
        t_sniff_eth0.start()
        t_sniff_eth1.start()
        t_detection.start()
        signal.pause()
    except KeyboardInterrupt:
        t_detection.stop()
        t_detection.join()
        __setdown()
        t_sniff_eth0.join()
        t_sniff_eth1.join()
        print("*** Stopping detection")


def configure():
    global L, alpha, tau
    L = input('Set Estimation Gain (L): ')
    alpha = input('Set Alpha (A): ')
    tau = input('Set Threshold (T): ')
    params()


def params():
    print('L: {} A: {} T: {}'.format(L, alpha, tau))


def __setup():
    global _stop_sniffer
    _stop_sniffer = False


def __setdown():
    global _stop_sniffer
    _stop_sniffer = True


if __name__ == '__main__':
    sys.exit(start())
