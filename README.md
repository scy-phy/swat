#Scapy implementation of DLR protocol

##Achieved:
1. DLR Frames

##ToDo:

####Traced, but not implemented:
  1. determine the length of all the reserved field
  2. conceive a better solution to solve the reserved field problem
  3. the IP&MAC address list in SignOn Frame

####Not Yet Traced:
  1. Neighbor Response (0x03), no clues how to capture
  2. Advertise (0x08), no clues how to capture
  3. Flush Tables (0x09), now clues how to capture
  4. Learning Update (0x0a), now clues how to capture

##Questions:
1. The unparsed part in frames following the reserved part, the strange part is that the changing frame length occurs only when the ring topology.
2. The entire length of Beacon frame.
3. In the vlan part, we cannot know the frametype, so the original frame has to splitted into 2 parts (solved)