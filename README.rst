============================================
SWaT's Ring Ethernet/IP dissectors for scapy
============================================

This repository contains a Python library which can be used to interact with components of the network using I/O implicit messages of a EtherNet/IP rings.
It uses scapy (http://www.secdev.org/projects/scapy/) to implement packet dissectors which are able to decode a part of the network traffic.
These dissectors can also be used to craft packets, which allows directly communicating with the PLCs (Programmable Logic Controllers) and RIO (Remote I/O) in the ring.

This project has been created to help analyzing the behavior of the SWaT (Secure Water Testbed), built at SUTD (Singapore University of Technology and Design).
Therefore, it strictly follows the design specifications in use by this system.

Requirements
============

* Python 2.7
* Scapy (http://www.secdev.org/projects/scapy/)

Interactive Mode
================

Starting interactive mode run::

    $ sudo python swat

    WARNING: No route found for IPv6 destination :: (no default route?)
    Welcome to Scapy (2.3.1)
    Add-on: Scapy Dissector for Ethernet/IP Implicit I/O messages
            at the Ring Level of the Secure Water Testbed (SWaT)
    >>>

Examples on PLC-DLR-1
---------------------

Reading Analog Inputs::

    >>> sniff(store=0, iface='eth0', prn=lambda p: show_p1_analog_inputs(p))
    level: 300 mm (1231) flow: 2.4 m^2/h (321)
    level: 300 mm (1232) flow: 2.4 m^2/h (321)
    level: 300 mm (1232) flow: 2.4 m^2/h (321)
    level: 301 mm (1233) flow: 2.4 m^2/h (321)
    .
    .
    .

Currently defined sniffing functions:

* Analog Inputs: show_p1_analog_inputs
* Wireless Analog Inputs: show_p1_w_analog_inputs (must be tested)
* Digital Inputs: show_p1_digital_inputs
* Digital Outputs: show_p1_digital_outputs
