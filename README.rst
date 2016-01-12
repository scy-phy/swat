========================================
Attack and Detection on the SWaT testbed
========================================

This repository contains the Attack (SWaTAssault) and Detection (SWaTCrawler) modules, developed to help on the
research of Intrusion Detection Systems for the Industrial Control System SWaT, a water treatment testbed built at SUTD
(Singapore University of Technology and Design). Therefore, their correct execution depend on the specific design and
implementation of such system.

Current attack and detection modules focus on the Level 0 (Device Level Rings) of SWaT.

Requirements
============

* Python 2.7
* Scapy (http://www.secdev.org/projects/scapy/)
* NetfilterQueue
* VLAN config utility

On Debian or Ubuntu, install these files with::

    apt-get install build-essential python-dev libnetfilter-queue-dev vlan

* Python bindings for NetfilterQueue (https://github.com/fqrouter/python-netfilterqueue). Install with `python setup.py`

In addition, python-scapy is required (install with apt-get)

Attacking with SWaTAssault
==========================

Coming Soon...

Detection with SWaTCrawler
==========================

Coming Soon...
