#Notes taken when learning DLR protocol

####Author: Bowei Yuan

###DLR motives:
The disadvantages of linear topology is that the failure of one node/the connection between to adjacent nodes may cause either side of the network unreachable. However, ring topologies implementated with DLR protocol could provide efficient fault detection and reconfiguration.
###DLR ring topology:
![DLR rings](http://www.iebmedia.com/images/art_images/IEB52_p10_1.jpg)

Each DLR ring is a separate network, each with at least one active ring supervisor. Each node in the DLR rings must have at leat 2 Ethernet ports and embedded switch technology.

* DLR supports simple, single ring topology, no multiple or overlapping rings. There may be more than one rings in a network installation, but those rings are strictly isolated, messages in one ring mustn't be present in another.
*  The switches to which a DLR switch is connected may be a non-DLR switch, possibly running a spanning tree network, but those switches will be blocked messages other than DLR messages, so that the ring network () won't be blocked.
*  switch ports to which DLR networks are connected should be configured properly, over-complicated combination of DLR topology and non-DLR topology would result in undesired chaos.

####DLR operations:
* DLR non-supervisor nodes:

 It is assumed that each DLR non-supervisor node has two ethernet ports, assumed implemented with embedded switches. When one non-supervisor node receives a packet, it has to decide whether the packet should be received by itself, or forward the packet to another node.

* DLR supervisor nodes:

1. The DLR supervisor nodes blocks one of its two ports, except for some special frames.
2. The DLR supervisor nodes doesn't forward the traffic on one ports to another, so that network loops can be avoided.
3. Beacons and Announces:

 ![Beacons and Announce](http://www.iebmedia.com/images/art_images/IEB52_p10_3.jpg)
	
	* The DLR supervisor sends one Beacon frame on both of its two ports per beacon interval(400 us default).
	* The DLR supervisor sends one Announce frame per second.
	* functionality of these 2 frames:
		1. the presence of Beacons and Announces informs the DLR nodes that it is currently a ring topology, instead of a linear one.
		2. at the supervisor, with the Beacon frames, some ring faults can be detected. (at non-supervisor nodes some ring faults can also be detected)
		3. the Beacon frames carry a precedence, which tells DLR nodes to select an active one when there are more than one supervisors.

 