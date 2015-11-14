__author__ = 'bernardyuan'
from scapy.config import conf
from scapy import all as scapy_all
from scapy import layers as layer


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
    # fld_list = []
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
            # scapy_all.StrLenField('Reserved', '', length_from=None),
        ],
        2: [
            # Neighbor Request
            # scapy_all.StrLenField('Reserved', '', length_from=None),
        ],
        3: [
            # Neighbor Response
        ],
        4: [
            # Link Status/Neighbor Status
            scapy_all.XShortField('Link/Neighbor_Status', -1),
            # scapy_all.StrLenField('Reserved', ''),
        ],
        5: [
            # Locate Fault
            # scapy_all.StrLenField('Reserved', ''),
        ],
        6: [
            # Announce
            scapy_all.XShortEnumField('Ring_State', -1, {
                0X01: 'RING_NORMAL_STATE',
                0x02: 'RING_FAULT_STATE'
            }),
            # scapy_all.StrLenField('Reserved', ''),
        ],
        7: [
            # SignOn
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

    # def __repr__(self):
    #     s = ""
    #     ct = conf.color_theme
    #     for f in self.fields_desc:
    #         if isinstance(f, ConditionalField) and not f._evalcond(self):
    #             continue
    #         if f.name in self.fld_list:
    #             val = f.i2repr(self, self.fields[f.name])
    #         elif f.name in self.overloaded_fields:
    #             val =  f.i2repr(self, self.overloaded_fields[f.name])
    #         else:
    #             continue
    #         if isinstance(f, Emph) or f in conf.emph:
    #             ncol = ct.emph_field_name
    #             vcol = ct.emph_field_value
    #         else:
    #             ncol = ct.field_name
    #             vcol = ct.field_value
    #
    #
    #         s += " %s%s%s" % (ncol(f.name),
    #                           ct.punct("="),
    #                           vcol(val))
    #     return "%s%s %s %s%s%s"% (ct.punct("<"),
    #                               ct.layer_name(self.__class__.__name__),
    #                               s,
    #                               ct.punct("|"),
    #                               repr(self.payload),
    #                               ct.punct(">"))
    # def show(self, indent=3, lvl="", label_lvl=""):
    #     """Prints a hierarchical view of the packet. "indent" gives the size of indentation for each layer."""
    #     ct = conf.color_theme
    #     print "%s%s %s %s" % (label_lvl,
    #                           ct.punct("###["),
    #                           ct.layer_name(self.name),
    #                           ct.punct("]###"))
    #     for f in self.fld_list:
    #         if isinstance(f, ConditionalField) and not f._evalcond(self):
    #             continue
    #         if isinstance(f, Emph) or f in conf.emph:
    #             ncol = ct.emph_field_name
    #             vcol = ct.emph_field_value
    #         else:
    #             ncol = ct.field_name
    #             vcol = ct.field_value
    #         fvalue = self.getfieldval(f.name)
    #         if isinstance(fvalue, Packet) or (f.islist and f.holds_packets and type(fvalue) is list):
    #             print "%s  \\%-10s\\" % (label_lvl+lvl, ncol(f.name))
    #             fvalue_gen = SetGen(fvalue,_iterpacket=0)
    #             for fvalue in fvalue_gen:
    #                 fvalue.show(indent=indent, label_lvl=label_lvl+lvl+"   |")
    #         else:
    #             begn = "%s  %-10s%s " % (label_lvl+lvl,
    #                                     ncol(f.name),
    #                                     ct.punct("="),)
    #             reprval = f.i2repr(self,fvalue)
    #             if type(reprval) is str:
    #                 reprval = reprval.replace("\n", "\n"+" "*(len(label_lvl)
    #                                                           +len(lvl)
    #                                                           +len(f.name)
    #                                                           +4))
    #             print "%s%s" % (begn,vcol(reprval))
    #     self.payload.show(indent=indent, lvl=lvl+(" "*indent*self.show_indent), label_lvl=label_lvl)


    def do_dissect(self, s):
        flist = self.fields_desc[:]
        fld_list = self.fields_desc[:]
        print flist
        flist.reverse()
        print flist
        raw = s
        while s and flist:
            f = flist.pop()
            s, fval = f.getfield(self, s)
            self.fields[f.name] = fval
            if f.name == 'Frame_Type':
                print fval
                print flist
                flist.reverse()
                print flist
                flist += self.frames[self.fields['Frame_Type']][:]
                fld_list += self.frames[self.fields['Frame_Type']]
                self.fields_desc = fld_list[:]
                print flist
                flist.reverse()
                print flist

        assert (raw.endswith(s))
        if s:
            self.raw_packet_cache = raw[:-len(s)]
        else:
            self.raw_packet_cache = raw
        self.explicit = 1
        return s

        # def guess_payload_class(self, payload):
        #     if self.Frame_Type == 1:
        #         return DlrBeacon
        #     else:
        #         return scapy_all.Packet.guess_payload_class(self, payload)
        #
        # def do_dissect_payload(self, s):
        #     cls = self.guess_payload_class(s)
        #     p = cls(s, _internal=1, _underlayer=self)
        #     p.add_underlayer(self)
        #     self.add_payload(p)


# class DlrBeacon(scapy_all.Packet):
#     name = 'Beacon'
#     fields_desc = [
#         scapy_all.ByteEnumField('Ring_State', None, {
#             1: 'Ring_Normal_State',
#             2: 'Ring_Fault_State'
#         }),
#         scapy_all.ByteField('Supervisor_Precedence', None),
#         scapy_all.ShortField('Beacon_Interval', None),
#         scapy_all.ShortField('Beacon_Timeout', None),
#         # There are some doubts on the length of this field
#         scapy_all.StrLenField('Reserved', '', length_from=None),
#     ]


# class DlrNeighborRequest(scapy_all.Packet):
#     name = 'NeighborRequest'
#     fields_desc = [
#         scapy_all.XShortField('Ring_SubType', -1),
#         scapy_all.XShortField('Ring_Protocol_Version', -1),
#         scapy_all.XShortEnumField('Frame_Type', -1, {
#             0x01: 'Beacon',
#             0x02: 'Neighbor_Reqest',
#             0x03: 'Neighbor_Response',
#             0x04: 'Link_State',
#             0x05: 'Locate_Fault',
#             0x06: 'Announce',
#             0x07: 'Sign_On',
#             0x08: 'Advertise',
#             0x09: 'Flush_Tables',
#             0x0a: 'Learning_Update'
#         }),
#         scapy_all.XShortEnumField('Source_Port', -1, {
#             0x00: 'Port1_or_Port2',
#             0x01: 'Port1',
#             0x02: 'Port2'
#         }),
#         scapy_all.LongField('Source_IP', -1),
#         scapy_all.XLongField('Sequence_ID', -1),
#         scapy_all.StrLenField('Reserved', '', length_from=None)
#     ]


# class DlrNeighborResponse(scapy_all.Packet):
#     name = 'NeighborResponse'
#     fields_desc = [
#         scapy_all.XShortField('Ring_SubType', -1),
#         scapy_all.XShortField('Ring_Protocol_Version', -1),
#         scapy_all.XShortEnumField('Frame_Type', -1, {
#             0x01: 'Beacon',
#             0x02: 'Neighbor_Reqest',
#             0x03: 'Neighbor_Response',
#             0x04: 'Link_State',
#             0x05: 'Locate_Fault',
#             0x06: 'Announce',
#             0x07: 'Sign_On',
#             0x08: 'Advertise',
#             0x09: 'Flush_Tables',
#             0x0a: 'Learning_Update'
#         }),
#         scapy_all.XShortEnumField('Source_Port', -1, {
#             0x00: 'Port1_or_Port2',
#             0x01: 'Port1',
#             0x02: 'Port2'
#         }),
#         scapy_all.LongField('Source_IP', -1),
#         scapy_all.XLongField('Sequence_ID', -1),
#
#     ]


# class DlrLinkState(scapy_all.Packet):
#     name = 'LinkState'
#     fields_desc = [
#         scapy_all.XShortField('Ring_SubType', -1),
#         scapy_all.XShortField('Ring_Protocol_Version', -1),
#         scapy_all.XShortEnumField('Frame_Type', -1, {
#             0x01: 'Beacon',
#             0x02: 'Neighbor_Reqest',
#             0x03: 'Neighbor_Response',
#             0x04: 'Link_State',
#             0x05: 'Locate_Fault',
#             0x06: 'Announce',
#             0x07: 'Sign_On',
#             0x08: 'Advertise',
#             0x09: 'Flush_Tables',
#             0x0a: 'Learning_Update'
#         }),
#         scapy_all.XShortEnumField('Source_Port', -1, {
#             0x00: 'Port1_or_Port2',
#             0x01: 'Port1',
#             0x02: 'Port2'
#         }),
#         scapy_all.LongField('Source_IP', -1),
#         scapy_all.XLongField('Sequence_ID', -1),
#         scapy_all.XShortField('Link/Neighbor_Status', -1),
#         scapy_all.StrLenField('Reserved', ''),
#
#     ]


# class DlrLocateFault(scapy_all.Packet):
#     name = 'LocateFault'
#     fields_desc = [
#         scapy_all.XShortField('Ring_SubType', -1),
#         scapy_all.XShortField('Ring_Protocol_Version', -1),
#         scapy_all.XShortEnumField('Frame_Type', -1, {
#             0x01: 'Beacon',
#             0x02: 'Neighbor_Reqest',
#             0x03: 'Neighbor_Response',
#             0x04: 'Link_State',
#             0x05: 'Locate_Fault',
#             0x06: 'Announce',
#             0x07: 'Sign_On',
#             0x08: 'Advertise',
#             0x09: 'Flush_Tables',
#             0x0a: 'Learning_Update'
#         }),
#         scapy_all.XShortEnumField('Source_Port', -1, {
#             0x00: 'Port1_or_Port2',
#             0x01: 'Port1',
#             0x02: 'Port2'
#         }),
#         scapy_all.LongField('Source_IP', -1),
#         scapy_all.XLongField('Sequence_ID', -1),
#         scapy_all.StrLenField('Reserved', ''),
#     ]


# class DlrAnnounce(scapy_all.Packet):
#     name = 'Announce'
#     fields_desc = [
#         scapy_all.XShortField('Ring_SubType', -1),
#         scapy_all.XShortField('Ring_Protocol_Version', -1),
#         scapy_all.XShortEnumField('Frame_Type', -1, {
#             0x01: 'Beacon',
#             0x02: 'Neighbor_Reqest',
#             0x03: 'Neighbor_Response',
#             0x04: 'Link_State',
#             0x05: 'Locate_Fault',
#             0x06: 'Announce',
#             0x07: 'Sign_On',
#             0x08: 'Advertise',
#             0x09: 'Flush_Tables',
#             0x0a: 'Learning_Update'
#         }),
#         scapy_all.XShortEnumField('Source_Port', -1, {
#             0x00: 'Port1_or_Port2',
#             0x01: 'Port1',
#             0x02: 'Port2'
#         }),
#         scapy_all.LongField('Source_IP', -1),
#         scapy_all.XLongField('Sequence_ID', -1),
#         scapy_all.XShortEnumField('Ring_State', -1, {
#             0X01: 'RING_NORMAL_STATE',
#             0x02: 'RING_FAULT_STATE'
#         }),
#         scapy_all.StrLenField('Reserved', '')
#
#     ]


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
        scapy_all.XShortEnumField('Source_Port', -1, {
            0x00: 'Port1_or_Port2',
            0x01: 'Port1',
            0x02: 'Port2'
        }),
        scapy_all.LongField('Source_IP', -1),
        scapy_all.XLongField('Sequence_ID', -1),
        scapy_all.XIntField('Num_nodes', -1),
        # implement with the PacketListField
        # scapy_all.FieldListField('Nodes_Info',None,),

        scapy_all.StrLenField('Reserved', '')
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
        scapy_all.XShortEnumField('Source_Port', -1, {
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
        scapy_all.XShortEnumField('Source_Port', -1, {
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
        scapy_all.XShortEnumField('Source_Port', -1, {
            0x00: 'Port1_or_Port2',
            0x01: 'Port1',
            0x02: 'Port2'
        }),
        scapy_all.LongField('Source_IP', -1),
        scapy_all.XLongField('Sequence_ID', -1),

    ]


scapy_all.bind_layers(layer.l2.Dot1Q, DLR, type=0x80e1)
# scapy_all.bind_layers(DlrBase,DlrBeacon,Frame_Type=1)
