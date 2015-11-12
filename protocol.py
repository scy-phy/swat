__author__ = 'bernardyuan'

from scapy import all as scapy_all


class DlrBase(scapy_all.Packet):
    name = 'DlrBaseClass'
    fields_desc = [
        scapy_all.XShortField('Ring_SubType', -1),
        scapy_all.XShortField('Ring_Protocol_Version', -1),
        scapy_all.XShortEnumField('Frame_Type', -1, {
            0x01: 'Beacon',
            0x02: 'Neighbor_Reqest',
            0x03: 'Neighbor_Response',
            0x04: 'Link_State',
            0x05: 'Locate_Fault',
            0x06: 'Announce',
            0x07: 'Sign_On',
            0x08: 'Advertise',
            0x09: 'Flush_Tables',
            0x0a: 'Learning_Update'
        }),
        scapy_all.XShortField('Source_Port', -1),
        scapy_all.XLongField('Source_IP', -1),
        scapy_all.XLongField('Sequence_ID', -1)
    ]


class DlrBeacon(DlrBase):
    name = 'Beacon'
    fields_desc = [
        scapy_all.XShortField('Ring_SubType', -1),
        scapy_all.XShortField('Ring_Protocol_Version', -1),
        scapy_all.XShortEnumField('Frame_Type', -1, {
            0x01: 'Beacon',
            0x02: 'Neighbor_Reqest',
            0x03: 'Neighbor_Response',
            0x04: 'Link_State',
            0x05: 'Locate_Fault',
            0x06: 'Announce',
            0x07: 'Sign_On',
            0x08: 'Advertise',
            0x09: 'Flush_Tables',
            0x0a: 'Learning_Update'
        }),
        scapy_all.XShortEnumField('Source_Port', -1,{
            0x00: 'Port1_or_Port2',
            0x01: 'Port1',
            0x02: 'Port2'
        }),
        scapy_all.LongField('Source_IP', -1),
        scapy_all.XLongField('Sequence_ID', -1),
        scapy_all.XShortEnumField('Ring_State', -1, {
            0x01: 'Ring_Normal_State',
            0x02: 'Ring_Fault_State'
        }),
        scapy_all.ShortField('Supervisor_Precedence', -1),
        scapy_all.LongField('Beacon_Interval', -1),
        scapy_all.LongField('Beacon_Timeout', -1),
        # There are some doubts on the length of this field
        scapy_all.StrLenField('Reserved', '', length_from=None),

    ]
class DlrNeighborReqest(scapy_all.Packet):
    name = 'NeighborRequest'
    fields_desc = [
        scapy_all.XShortField('Ring_SubType', -1),
        scapy_all.XShortField('Ring_Protocol_Version', -1),
        scapy_all.XShortEnumField('Frame_Type', -1, {
            0x01: 'Beacon',
            0x02: 'Neighbor_Reqest',
            0x03: 'Neighbor_Response',
            0x04: 'Link_State',
            0x05: 'Locate_Fault',
            0x06: 'Announce',
            0x07: 'Sign_On',
            0x08: 'Advertise',
            0x09: 'Flush_Tables',
            0x0a: 'Learning_Update'
        }),
        scapy_all.XShortEnumField('Source_Port', -1,{
            0x00: 'Port1_or_Port2',
            0x01: 'Port1',
            0x02: 'Port2'
        }),
        scapy_all.LongField('Source_IP', -1),
        scapy_all.XLongField('Sequence_ID', -1),
        scapy_all.StrLenField('Reserved','',length_from=None)
    ]

class DlrNeighborResponse(scapy_all.Packet):
    name = 'NeighborResponse'
    fields_desc = [
        scapy_all.XShortField('Ring_SubType', -1),
        scapy_all.XShortField('Ring_Protocol_Version', -1),
        scapy_all.XShortEnumField('Frame_Type', -1, {
            0x01: 'Beacon',
            0x02: 'Neighbor_Reqest',
            0x03: 'Neighbor_Response',
            0x04: 'Link_State',
            0x05: 'Locate_Fault',
            0x06: 'Announce',
            0x07: 'Sign_On',
            0x08: 'Advertise',
            0x09: 'Flush_Tables',
            0x0a: 'Learning_Update'
        }),
        scapy_all.XShortEnumField('Source_Port', -1,{
            0x00: 'Port1_or_Port2',
            0x01: 'Port1',
            0x02: 'Port2'
        }),
        scapy_all.LongField('Source_IP', -1),
        scapy_all.XLongField('Sequence_ID', -1),

    ]
class DlrLinkState(scapy_all.Packet):
    name = 'LinkState'
    fields_desc = [
        scapy_all.XShortField('Ring_SubType', -1),
        scapy_all.XShortField('Ring_Protocol_Version', -1),
        scapy_all.XShortEnumField('Frame_Type', -1, {
            0x01: 'Beacon',
            0x02: 'Neighbor_Reqest',
            0x03: 'Neighbor_Response',
            0x04: 'Link_State',
            0x05: 'Locate_Fault',
            0x06: 'Announce',
            0x07: 'Sign_On',
            0x08: 'Advertise',
            0x09: 'Flush_Tables',
            0x0a: 'Learning_Update'
        }),
        scapy_all.XShortEnumField('Source_Port', -1,{
            0x00: 'Port1_or_Port2',
            0x01: 'Port1',
            0x02: 'Port2'
        }),
        scapy_all.LongField('Source_IP', -1),
        scapy_all.XLongField('Sequence_ID', -1),
        scapy_all.XShortField('Link/Neighbor_Status',-1),
        scapy_all.StrLenField('Reserved',''),

    ]

class DlrLocateFault(scapy_all.Packet):
    name = 'LocateFault'
    fields_desc = [
        scapy_all.XShortField('Ring_SubType', -1),
        scapy_all.XShortField('Ring_Protocol_Version', -1),
        scapy_all.XShortEnumField('Frame_Type', -1, {
            0x01: 'Beacon',
            0x02: 'Neighbor_Reqest',
            0x03: 'Neighbor_Response',
            0x04: 'Link_State',
            0x05: 'Locate_Fault',
            0x06: 'Announce',
            0x07: 'Sign_On',
            0x08: 'Advertise',
            0x09: 'Flush_Tables',
            0x0a: 'Learning_Update'
        }),
        scapy_all.XShortEnumField('Source_Port', -1,{
            0x00: 'Port1_or_Port2',
            0x01: 'Port1',
            0x02: 'Port2'
        }),
        scapy_all.LongField('Source_IP', -1),
        scapy_all.XLongField('Sequence_ID', -1),
        scapy_all.StrLenField('Reserved',''),
    ]

class DlrAnnounce(scapy_all.Packet):
    name = 'Announce'
    fields_desc = [
        scapy_all.XShortField('Ring_SubType', -1),
        scapy_all.XShortField('Ring_Protocol_Version', -1),
        scapy_all.XShortEnumField('Frame_Type', -1, {
            0x01: 'Beacon',
            0x02: 'Neighbor_Reqest',
            0x03: 'Neighbor_Response',
            0x04: 'Link_State',
            0x05: 'Locate_Fault',
            0x06: 'Announce',
            0x07: 'Sign_On',
            0x08: 'Advertise',
            0x09: 'Flush_Tables',
            0x0a: 'Learning_Update'
        }),
        scapy_all.XShortEnumField('Source_Port', -1,{
            0x00: 'Port1_or_Port2',
            0x01: 'Port1',
            0x02: 'Port2'
        }),
        scapy_all.LongField('Source_IP', -1),
        scapy_all.XLongField('Sequence_ID', -1),
        scapy_all.XShortEnumField('Ring_State',-1,{
            0X01: 'RING_NORMAL_STATE',
            0x02: 'RING_FAULT_STATE'
        }),
        scapy_all.StrLenField('Reserved','')

    ]

class DlrSignOn(scapy_all.Packet):
    name = 'SignOn'
    fields_desc = [
        scapy_all.XShortField('Ring_SubType', -1),
        scapy_all.XShortField('Ring_Protocol_Version', -1),
        scapy_all.XShortEnumField('Frame_Type', -1, {
            0x01: 'Beacon',
            0x02: 'Neighbor_Reqest',
            0x03: 'Neighbor_Response',
            0x04: 'Link_State',
            0x05: 'Locate_Fault',
            0x06: 'Announce',
            0x07: 'Sign_On',
            0x08: 'Advertise',
            0x09: 'Flush_Tables',
            0x0a: 'Learning_Update'
        }),
        scapy_all.XShortEnumField('Source_Port', -1,{
            0x00: 'Port1_or_Port2',
            0x01: 'Port1',
            0x02: 'Port2'
        }),
        scapy_all.LongField('Source_IP', -1),
        scapy_all.XLongField('Sequence_ID', -1),
        scapy_all.XIntField('Num_nodes',-1),
        # implement with the PacketListField
        # scapy_all.FieldListField('Nodes_Info',None,),

        scapy_all.StrLenField('Reserved','')
    ]

class DlrAdvertise(scapy_all.Packet):
    name = 'Advertise'
    fields_desc = [
        scapy_all.XShortField('Ring_SubType', -1),
        scapy_all.XShortField('Ring_Protocol_Version', -1),
        scapy_all.XShortEnumField('Frame_Type', -1, {
            0x01: 'Beacon',
            0x02: 'Neighbor_Reqest',
            0x03: 'Neighbor_Response',
            0x04: 'Link_State',
            0x05: 'Locate_Fault',
            0x06: 'Announce',
            0x07: 'Sign_On',
            0x08: 'Advertise',
            0x09: 'Flush_Tables',
            0x0a: 'Learning_Update'
        }),
        scapy_all.XShortEnumField('Source_Port', -1,{
            0x00: 'Port1_or_Port2',
            0x01: 'Port1',
            0x02: 'Port2'
        }),
        scapy_all.LongField('Source_IP', -1),
        scapy_all.XLongField('Sequence_ID', -1),

    ]

class DlrFlushTable(scapy_all.Packet):
    name = 'FlushTable'
    fields_desc = [
        scapy_all.XShortField('Ring_SubType', -1),
        scapy_all.XShortField('Ring_Protocol_Version', -1),
        scapy_all.XShortEnumField('Frame_Type', -1, {
            0x01: 'Beacon',
            0x02: 'Neighbor_Reqest',
            0x03: 'Neighbor_Response',
            0x04: 'Link_State',
            0x05: 'Locate_Fault',
            0x06: 'Announce',
            0x07: 'Sign_On',
            0x08: 'Advertise',
            0x09: 'Flush_Tables',
            0x0a: 'Learning_Update'
        }),
        scapy_all.XShortEnumField('Source_Port', -1,{
            0x00: 'Port1_or_Port2',
            0x01: 'Port1',
            0x02: 'Port2'
        }),
        scapy_all.LongField('Source_IP', -1),
        scapy_all.XLongField('Sequence_ID', -1),

    ]

class DlrLearningUpdate(scapy_all.Packet):
    name = 'LearningUpdate'
    fields_desc = [
        scapy_all.XShortField('Ring_SubType', -1),
        scapy_all.XShortField('Ring_Protocol_Version', -1),
        scapy_all.XShortEnumField('Frame_Type', -1, {
            0x01: 'Beacon',
            0x02: 'Neighbor_Reqest',
            0x03: 'Neighbor_Response',
            0x04: 'Link_State',
            0x05: 'Locate_Fault',
            0x06: 'Announce',
            0x07: 'Sign_On',
            0x08: 'Advertise',
            0x09: 'Flush_Tables',
            0x0a: 'Learning_Update'
        }),
        scapy_all.XShortEnumField('Source_Port', -1,{
            0x00: 'Port1_or_Port2',
            0x01: 'Port1',
            0x02: 'Port2'
        }),
        scapy_all.LongField('Source_IP', -1),
        scapy_all.XLongField('Sequence_ID', -1),

    ]

