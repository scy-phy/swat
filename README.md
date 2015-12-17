#Scapy implementation of DLR protocol

## Introduction
This module implements [DLR](http://www.iebmedia.com/index.php?id=6113&parentid=63&themeid=255&showdetail=true) (Device Level Ring) protocol with [Scapy](http://www.secdev.org/projects/scapy/doc/usage.html), which will be applied to miniCPS for Cyber Security Research on SWaT testbed at SUTD.

## Enrionment Setup
The following elements are required for environment set up.

1. Python 2.7.10
2. Scapy 2.3.1

## How to use this module
The main purpose of this module is to help dissect and fabricate DLR packets with python programming language. The development is based on the Base class provided by Scapy and some functions are overridden for some particular use.

### Packet Dissection
1. import this module and Scapy

		from scapy import all
		import DLR
2. Then you can listen on one interface on your machine, then the packets with DLR features would be automatically dissected and parsed.

### Packet Fabrication
#### Method 1, build from dictionaries

If each field of a DLR packet is known and provided, you can provide a DLR packet with this module from a dict containing those fields, the parameter should be passed to the class constructor as key words parameters in python.

	dict = {"FieldA":"ValueA","FieldB":"ValueB"}
	packet = DLR.DLR(**dict)

The "packet" is the newly fabricated packet, and you can stack it with other headers in addition. For instance, add a Ethernet/IP Header:

	from scapy import layers
	dict0 = {"EtherField":"EtherFieldValue"}
	dict1 = {"DLRField":"DLRFieldValue"}
	packet = layers.l2.Ether(**dict0)/DLR.DLR(**dict1)

**[Attention]** If your application requires the hexdump or string format of the newly fabricated packets, some extra steps need to be done before applying hexdump() or str() function to the packet.

	#It is a MUST to manually set explicit value
	#of each layer to 1 before converting the packet
	
	#suppose there are only 2 layers
	packet.explict = 1
	packet.payload.explicit = 1
	
This is because of some very 'dynamic' tricks when dissecting DLR packets, as we cannot know the specific type of frames of a certain packet until it is partly dissected, the rest fields must be dynamically added to a new packet in accordance with its frame type.

With Method2 such hassles can be avoided.

####Method 2, build from bytes

If you have a dissected packet, this method is preferred.

With str() method or build() method of a packet you can get it's raw string format, so it would be more convinient to directly build new packets with raw string.

	a = #an dissected packet
	raw_string = str(a) #get the raw string
	packet = DLR.DLR(raw_string)
	
	# Ok, now you can do any reverse engineering on the 
	# new packet as you wish!

The reason why this method works is that when the module build packet from raw_string, it could automatically change the explicit value into 1.
	