#Scapy implementation of DLR protocol

##Achieved:
1. DLR Beacon frame (0x01)


##ToDo:
####Traced, but not implemented:
  1. Neighbor Request (0x02)
  2. Link Status/Neighbor Status (0x04)
  3. Locate Fault (0x05)
  4. Announce (0x06)
  5. Sign On (0x07)

####Not Yet Traced:
  1. Neighbor Response (0x03), no clues how to capture
  2. Advertise (0x08), no clues how to capture
  3. Flush Tables (0x09), now clues how to capture
  4. Learning Update (0x0a), now clues how to capture

##Questions:
1. The unparsed part in frames following the reserved part, the strange part is that the changing frame length occurs only when the ring topology.
2. The entire length of Beacon frame.
