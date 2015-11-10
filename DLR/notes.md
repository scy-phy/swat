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

###DLR operations:
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

###DLR Failure States:
* Some common failure cases:
	1. link/physical layer failure recognised by adjacent nodes.
	2. power failure or power cycling failure on a ring node, recognised by adjacent nodes.
	3. Intentional media disconnect by the user, for plugging a new node or removing an existing node.

In cases described above, the adjacent node who detects the failure would send a Link_Status message to the supervisor.

* Aftering receiving the Link_Status message, the (active) supervisor would:
	1. reconfigure the network by unblocking the previous blocked ethernet port on the other side, then flush its unicast MAC table.
	2. immediately send Beacons and Announces informing ring nodes that the ring is currently faulted.
	3. now the supervisor passes traffics through both of its ports.

* The ring nodes also have following actions:
	1.  flushing their respective unicast MAC table upon the direction where receives Link_Status message or the direction where it receives Beacon/Announce frames.
* Uncommon failures:
	1. physical layer and power supply works fine, but some higher layer factors, hardware/firmware fails leading to traffic loss.
	2. some protocol unaware nodes are newly plugged into the ring. The active ring supervisor would detect Beacon frames loss on both of its ports and then send a Locate_Fault frame to diagnose the location of fualts.
	3. Another possible fault is partial network fault. Traffic loss occurs on one particular direction. The active supervisor may detect this by monitoring Beacon frames on its ports. When such traffic loss detected, it would block one port and set a value in DLR object, user interventiion required.
	4. if a series of rapid failure/restore cycles occur because of reasons like faulty connector, such condition would result in network instability and is hard to diagnose, the supervisor would set a status value in DLR object and user has to explicitly clear the errors.