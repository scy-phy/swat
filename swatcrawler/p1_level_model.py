from __future__ import print_function
import ctypes
import math
import threading
import commons.util

from scapy import all as scapy_all

import swat
import scaling
import filters

valve = 0
pump = 0
rlevel = 0
real_level = 0
est_level = 0.831
L = 0.1
T = 0.005
cusum = 0

ALPHA = 0.0005
FLOW = 2.5  # Water flow in m^3/h
DIA = 1.38  # Tank 1 diameter


def get_model_parameters(packet):
    if swat.SWAT_P1_RIO_AI in packet:
        global real_level
        l = ctypes.c_short(packet[swat.SWAT_P1_RIO_AI].level)
        l = filters.scale(l.value, scaling.P1Level)
        real_level = l * 0.001

    if swat.SWAT_P1_RIO_DI in packet:
        global valve, pump
        valve = packet[swat.SWAT_P1_RIO_DI].valve_open
        pump = packet[swat.SWAT_P1_RIO_DI].pump1_run


def calculate_estimated():
    global valve, pump, real_level, est_level, cusum
    u = FLOW / (3600 * math.pi * math.pow(DIA / 2, 2))  # Water volume change
    u *= valve - pump  # Direction of water volume change
    est_level = est_level + u + L * (real_level - est_level)

    cusum += abs(real_level - est_level) - ALPHA
    cusum = max(cusum, 0)

    # print('{} {}'.format(valve, pump), end=' ')
    print('{},{},{},{}'.format(rlevel, real_level, abs(real_level - est_level), cusum), end='')
    # if abs(real_level - est_level) > T:
    if cusum > T:
        cusum = 0
        print(', SWaTAssault detected!!!!')
    else:
        print('')


def read_real_level(packet):
    if swat.SWAT_P1_RIO_AI in packet:
        l = ctypes.c_short(packet[swat.SWAT_P1_RIO_AI].level).value
        slevel = ctypes.c_short(packet[swat.SWAT_P1_RIO_AI].level)
        l = filters.scale(slevel.value, scaling.P1Level)
        global rlevel
        rlevel = l * 0.001


def start():
    # try:
    t_sniff_eth0 = threading.Thread(target=scapy_all.sniff,
                                    kwargs={'iface': 'eth0', 'store': 0,
                                            'prn': lambda p: read_real_level(p)})
    # t_sniff_eth1 = threading.Thread(target=scapy_all.sniff,
    #                                        kwargs={'iface': 'eth1', 'store': 0,
    #                                                'prn': lambda p: get_model_parameters(p)})
    t_detection = commons.util.RepeatEvery(1, calculate_estimated)
    print("*** Starting detection")
    t_detection.start()
    t_sniff_eth0.start()
    # t_sniff_eth1.start()
    scapy_all.sniff(iface='eth1', store=0, prn=lambda p: get_model_parameters(p))
    # except KeyboardInterrupt:
    t_detection.stop()
    t_detection.join()
    t_sniff_eth0.join()
    print("*** Stopping detection")


def configure():
    pass


def params():
    pass


if __name__ == '__main__':
    start()
