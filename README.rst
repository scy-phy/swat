SWaT's Ring Ethernet/IP dissectors for scapy
============================================

This repository contains a Python library which can be used to interact with components of the network using I/O implicit messages of a EtherNet/IP rings.
It uses scapy (http://www.secdev.org/projects/scapy/) to implement packet dissectors which are able to decode a part of the network traffic.
These dissectors can also be used to craft packets, which allows directly communicating with the PLCs (Programmable Logic Controllers) and RIO (Remote I/O) in the ring.

This project has been created to help analyzing the behavior of the SWaT (Secure Water Testbed), built at SUTD (Singapore University of Technology and Design).
Therefore, it strictly follows the design specifications in use by this system.

Requirements
------------

* Python 2.7
* Scapy (http://www.secdev.org/projects/scapy/)
