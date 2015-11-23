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
"""Sniffing functions to be used as parameter prn of the "sniff" command in
Scapy 2.3.1.
"""
from __future__ import print_function

import ctypes

import scaling
import swat
from scaling import current_to_signal


def show_p1_analog_inputs(packet):
    if swat.SWAT_P1_RIO_AI in packet:
        level = ctypes.c_short(packet[swat.SWAT_P1_RIO_AI].level).value
        flow = ctypes.c_short(packet[swat.SWAT_P1_RIO_AI].flow).value
        slevel = ctypes.c_short(packet[swat.SWAT_P1_RIO_AI].level)
        sflow = ctypes.c_short(packet[swat.SWAT_P1_RIO_AI].flow)
        slevel = current_to_signal(slevel.value, scaling.P1Level)
        sflow = current_to_signal(sflow.value, scaling.P1Flow)
        print('level: {:2f} mm ({}) flow: {:2f} m^2/h ({})'.format(slevel, level, sflow, flow))


def show_p1_w_analog_inputs(packet):
    if swat.SWAT_P1_WRIO_AI in packet:
        level = ctypes.c_short(packet[swat.SWAT_P1_WRIO_AI].level).value
        flow = ctypes.c_short(packet[swat.SWAT_P1_WRIO_AI].flow).value
        slevel = ctypes.c_short(packet[swat.SWAT_P1_WRIO_AI].level)
        sflow = ctypes.c_short(packet[swat.SWAT_P1_WRIO_AI].flow)
        slevel = current_to_signal(slevel.value, scaling.P1Level)
        sflow = current_to_signal(sflow.value, scaling.P1Flow)
        print('level: {:2f} mm ({}) flow: {:2f} m^2/h ({})'.format(slevel, level, sflow, flow))


def show_p1_digital_inputs(packet):
    if swat.SWAT_P1_RIO_DI in packet:
        s = 'plc_wireless: ({})\n'.format(packet[swat.SWAT_P1_RIO_DI].plc_wireless)
        s += 'rio_wireless: ({})\n'.format(packet[swat.SWAT_P1_RIO_DI].rio_wireless)
        s += 'pump1_auto: ({})\n'.format(packet[swat.SWAT_P1_RIO_DI].pump1_auto)
        s += 'pump1_run: ({})\n'.format(packet[swat.SWAT_P1_RIO_DI].pump1_run)
        s += 'pump1_fault: ({})\n'.format(packet[swat.SWAT_P1_RIO_DI].pump1_fault)
        s += 'pump2_auto: ({})\n'.format(packet[swat.SWAT_P1_RIO_DI].pump2_auto)
        s += 'pump2_run: ({})\n'.format(packet[swat.SWAT_P1_RIO_DI].pump2_run)
        s += 'pump2_fault: ({})\n'.format(packet[swat.SWAT_P1_RIO_DI].pump2_fault)
        s += 'valve_open: ({})\n'.format(packet[swat.SWAT_P1_RIO_DI].valve_open)
        s += 'valve_close: ({})\n'.format(packet[swat.SWAT_P1_RIO_DI].valve_close)
        print(s)


def show_p1_digital_outputs(packet):
    if swat.SWAT_P1_RIO_DO in packet:
        if packet[swat.SWAT_P1_RIO_DO].number == 1:
            s = 'counter: ({})\n'.format(packet[swat.SWAT_P1_RIO_DO].counter)
            s += 'valve_close: ({})\n'.format(packet[swat.SWAT_P1_RIO_DO].valve_close)
            s += 'valve_open: ({})\n'.format(packet[swat.SWAT_P1_RIO_DO].valve_open)
            s += 'pump2_start: ({})\n'.format(packet[swat.SWAT_P1_RIO_DO].pump2_start)
            s += 'pump1_start: ({})\n'.format(packet[swat.SWAT_P1_RIO_DO].pump1_start)
            print(s)
