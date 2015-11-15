__author__ = 'bernardyuan'
from scapy import all as scapy_all
from scapy import layers as layer

# class DlrReservedField(scapy_all.StrField):
#     def __init__(self, name, default, fmt='H', maxlen=64):
#         scapy_all.StrField.__init__(self, name, default, fmt)
#         self.maxlen = maxlen
#
#     def getfield(self, pkt, s):
#         print s[self.maxlen-len(pkt):]
#         print self.m2i(pkt,s[0:self.maxlen - len(pkt)])
#         return s[self.maxlen - len(pkt):], self.m2i(pkt, s[0:self.maxlen - len(pkt)])


# class DlrSignOnInfo()

class DLR(scapy_all.Packet):
    name = 'DLR'
    fields_desc = [
        scapy_all.XByteField('Ring_SubType', None),
        scapy_all.XByteField('Ring_Protocol_Version', None),
        scapy_all.ByteEnumField('Frame_Type', None, {
            1: 'Beacon',
            2: 'Neighbor_Request',
            3: 'Neighbor_Response',
            4: 'Link_State',
            5: 'Locate_Fault',
            6: 'Announce', 7: 'Sign_On',
            8: 'Advertise',
            9: 'Flush_Tables',
            10: 'Learning_Update'
        }),
        scapy_all.ByteField('Source_Port', None),
        scapy_all.IPField('Source_IP', None),
        scapy_all.XIntField('Sequence_ID', None)
    ]
    frames = {
        # zero means nothing
        0: [],
        1: [
            # Beacon Frame
            scapy_all.ByteEnumField('Ring_State', None, {
                1: 'Ring_Normal_State',
                2: 'Ring_Fault_State'
            }),
            scapy_all.ByteField('Supervisor_Precedence', None),
            scapy_all.IntField('Beacon_Interval', None),
            scapy_all.IntField('Beacon_Timeout', None),
            # There are some doubts on the length of this field
            # scapy_all.StrFixedLenField('Reserved', None,length=32),
            scapy_all.StrField('Reserved',None),
        ],
        2: [
            # Neighbor Request
            scapy_all.StrField('Reserved',None),
            # DlrReservedField('Reserved', ""),
        ],
        3: [
            # Neighbor Respnse
        ],
        4: [
            # Link Status/Neighbor Status
            scapy_all.XByteField('Link/Neighbor_Status', None),
            scapy_all.StrField('Reserved',None),
            # DlrReservedField('Reserved', ""),
        ],
        5: [
            # Locate Fault
            scapy_all.StrField('Reserved',None),
            # DlrReservedField('Reserved', ""),
        ],
        6: [
            # Announce
            scapy_all.ByteEnumField('Ring_State', None, {
                0X01: 'RING_NORMAL_STATE',
                0x02: 'RING_FAULT_STATE'
            }),
            scapy_all.StrField('Reserved',None),
            # DlrReservedField('Reserved', ""),
        ],
        7: [
            # SignOn
            scapy_all.StrField('Reserved',None),
        ],
        8: [
            # Advertise
        ],
        9: [
            # Flush Table
        ],
        10: [
            # Learing Update
        ],
    }

    def do_dissect(self, s):
        flist = self.fields_desc[:]
        fld_list = self.fields_desc[:]
        flist.reverse()
        raw = s
        while s and flist:
            f = flist.pop()
            s, fval = f.getfield(self, s)
            self.fields[f.name] = fval
            if f.name == 'Frame_Type':
                flist.reverse()
                flist += self.frames[self.fields['Frame_Type']][:]
                fld_list += self.frames[self.fields['Frame_Type']]
                self.fields_desc = fld_list[:]
                flist.reverse()
        assert (raw.endswith(s))
        if s:
            self.raw_packet_cache = raw[:-len(s)]
        else:
            self.raw_packet_cache = raw
        self.explicit = 1
        return s


scapy_all.bind_layers(layer.l2.Dot1Q, DLR, type=0x80e1)
# scapy_all.bind_layers(DlrBase,DlrBeacon,Frame_Type=1)
