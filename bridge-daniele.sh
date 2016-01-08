#!/bin/bash

# http://www.linuxfoundation.org/collaborate/workgroups/networking/bridge
# run as root
# Script to set up bridge if /etc/network/interfaces is not used

# my machine gives funny names to the interfaces
ETH0=eth2
ETH1=enx00051ba139b9

# up is implicit
ifconfig $ETH0 0.0.0.0
ifconfig $ETH1 0.0.0.0

# for more info type: man 8 brctl
brctl addbr br0
brctl addif br0 $ETH0
brctl addif br0 $ETH1

# debug
brctl show 

# do not use MAC tables
brctl setageing br0 0

# disable spanning tree protocol
brctl stp  br0 off

ifconfig br0 up

# debug
brctl showbr br0
brctl showmacs br0

