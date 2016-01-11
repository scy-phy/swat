#!/bin/bash
# run this as root for now
# Script to set up bridge if /etc/network/interfaces is not used
# This will also enable VLAN 0 message reception on eth0.0 and eth1.0
# install vlan support with apt-get install vlan



# my machine gives funny names to the interfaces
ETH0=eth2
ETH1=enx00051ba139b9

service network-manager stop
modprobe 8021q
ifconfig $ETH0 up
ifconfig $ETH1 up

vconfig add $ETH0 0
vconfig add $ETH1 0
ifconfig $ETH0.0 up
ifconfig $ETH1.0 up

brctl addbr br0
brctl addif br0 $ETH0.0
brctl addif br0 $ETH1.0
brctl addif br0 $ETH0
brctl addif br0 $ETH1

brctl setageing br0 0
brctl stp  br0 off
ifconfig br0 up

