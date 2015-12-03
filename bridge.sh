#!/bin/bash
# run this as root for now
# Script to set up bridge if /etc/network/interfaces is not used

# my machine gives funny names to the interfaces
ETH0=eth2
ETH1=enx00051ba139b9

ifconfig $ETH0 up
ifconfig $ETH1 up

brctl addbr br0
brctl addif br0 $ETH0 $ETH1
brctl setageing br0 0
brctl stp  br0 off
ifconfig br0 up
