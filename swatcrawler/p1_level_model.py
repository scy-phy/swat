from __future__ import print_function, division
import ctypes
import math
import threading
import sys
import signal

from scapy import all as scapy_all

import commons.util
import swat
import scaling
import filters

valve = 0
pump = 0

olevel = 0.695
rlevel = 0.695
elevel = 0.695

L = 0.1
tau = 0.1
alpha = 0.005
cusum = 0

FLOW = 2.5  # Water flow in m^3/h
DIA = 1.38  # Tank 1 diameter

stop_sniffer = False


def get_model_parameters(packet):
    if swat.SWAT_P1_RIO_AI in packet:
        global rlevel
        l = ctypes.c_short(packet[swat.SWAT_P1_RIO_AI].level)
        l = filters.scale(l.value, scaling.P1Level)
        rlevel = l * 0.001

    if swat.SWAT_P1_RIO_DI in packet:
        global valve, pump
        valve = packet[swat.SWAT_P1_RIO_DI].valve_open
        pump = packet[swat.SWAT_P1_RIO_DI].pump1_run


def calculate_cusum():
    global valve, pump, rlevel, elevel, cusum
    u = FLOW / (3600 * math.pi * math.pow(DIA / 2, 2))  # Water volume change
    u *= valve - pump  # Direction of water volume change
    elevel = elevel + u + L * (rlevel - elevel)

    cusum += abs(rlevel - elevel) - alpha
    cusum = max(cusum, 0)

    # print('{} {}'.format(valve, pump), end=' ')
    print('{},{},{},{},{}'.format(olevel, rlevel, elevel, abs(rlevel - elevel), cusum), end='')
    # if abs(rlevel - elevel) > T:
    if cusum > tau:
        cusum = 0
        print(', SWaTAssault detected!!!!')
    else:
        print('')


def read_real_level(packet):
    if swat.SWAT_P1_RIO_AI in packet:
        l = ctypes.c_short(packet[swat.SWAT_P1_RIO_AI].level).value
        slevel = ctypes.c_short(packet[swat.SWAT_P1_RIO_AI].level)
        l = filters.scale(slevel.value, scaling.P1Level)
        global olevel
        olevel = l * 0.001


def stop(p):
    global stop_sniffer
    return stop_sniffer


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
    global stop_sniffer
    stop_sniffer = False


def __setdown():
    global stop_sniffer
    stop_sniffer = True


if __name__ == '__main__':
    sys.exit(start())
