__author__ = 'bernardyuan'
from scapy import all as scapy_all
from scapy import layers as layer
import struct,time
# class DlrReservedField(scapy_all.StrField):
#     def __init__(self, name, default, fmt='H', maxlen=64):
#         scapy_all.StrField.__init__(self, name, default, fmt)
#         self.maxlen = maxlen
#
#     def getfield(self, pkt, s):
#         print s[self.maxlen-len(pkt):]
#         print self.m2i(pkt,s[0:self.maxlen - len(pkt)])
#         return s[self.maxlen - len(pkt):], self.m2i(pkt, s[0:self.maxlen - len(pkt)])


class DlrSignOnInfoList(scapy_all.Field):
    cls_list = [scapy_all.MACField('MACAddress',None),scapy_all.IPField('IPAddress',None)]
    def __init__(self, name, default, fmt="H"):
        self.name = name
        if fmt[0] in "@=<>!":
            self.fmt = fmt
        else:
            self.fmt = "!"+fmt
        self.default = self.any2i(None,default)
        self.sz = struct.calcsize(self.fmt)
        self.owners = []
        self.fields = {}
    def getfield(self, pkt, s):
        nn = pkt.fields["Node_Num"]
        i = 0
        self.fields["MACAddress"] = []
        self.fields["IPAddress"] = []
        while i < nn:
            ccls = self.cls_list[0]
            s, fval = ccls.getfield(self,s)
            self.fields["MACAddress"].append(fval)
            ccls = self.cls_list[1]
            s, fval = ccls.getfield(self, s)
            self.fields["IPAddress"].append(fval)
            i += 1
        return s, self.fields
    def addfield(self, pkt, s, val):
        i = 0
        nn = pkt.fields["Node_Num"]
        while i<nn:
            ccls = self.cls_list[0]
            s = ccls.addfield(pkt,s,self.fields["MACAddress"][i])
            ccls = self.cls_list[1]
            s = ccls.addfield(pkt,s,self.fields["IPAddress"][i])
            i += 1
        return s
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
            6: 'Announce',
            7: 'Sign_On',
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
            scapy_all.BitEnumField('Link/Neighbor_Status_Frame_Type',None,1,{
                1:'Neighbor_Status_Frame',
                0:'Link_Status_Frame'
            }),
            scapy_all.BitField('Link/Neighbor_Status_Reserved',None, 5),
            scapy_all.BitEnumField('Port2_Active',None,1,{
                1:"True",
                0:"False"
            }),
            scapy_all.BitEnumField("Port1_Active",None,1,{
                1:"True",
                0:"False"
            }),
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
            scapy_all.ShortField('Node_Num',0),
            DlrSignOnInfoList('SignOnInfo',None),
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
    def __init__(self, _pkt="", post_transform=None, _internal=0, _underlayer=None, **fields):
        self.time  = time.time()
        self.sent_time = 0
        if self.name is None:
            self.name = self.__class__.__name__
        self.aliastypes = [ self.__class__ ] + self.aliastypes
        self.default_fields = {}
        self.overloaded_fields = {}
        self.fields={}
        self.fieldtype={}
        self.packetfields=[]
        self.__dict__["payload"] = scapy_all.NoPayload()
        print "int init, pkt:",scapy_all.hexdump(_pkt), " fields:",fields
        # add more fields into field_desc according to the value of 'Frame_Type' field
        field_list = self.fields_desc[:]
        if fields and 'Frame_Type' in fields:
            print "bernard add attributes"
            field_list += self.frames[fields['Frame_Type']][:]
            self.fields_desc = field_list[:]
        self.init_fields()
        self.underlayer = _underlayer
        self.initialized = 1
        self.original = _pkt
        if _pkt:
            print "building from pkt"
            self.dissect(_pkt)
            if not _internal:
                self.dissection_done(self)
        if fields:
            self.explicit =1
        for f in fields.keys():
            print "fields are not empty:",f
            self.fields[f] = self.get_field(f).any2i(self,fields[f])
        if type(post_transform) is list:
            print "type post transform is list"
            self.post_transforms = post_transform
        elif post_transform is None:
            print "post_transform is None"
            self.post_transforms = []
        else:
            print "neither none or list"
            self.post_transforms = [post_transform]
        if fields:
            self.raw_packet_cache = self.do_build()
        if self.underlayer:
            self.underlayer.explicit =1
            if self.underlayer.underlayer:
                self.underlayer.underlayer.explicit = 1
    def copy(self):
        """Returns a deep copy of the instance."""
        clone = self.__class__(**self.fields)
        clone.default_fields = self.default_fields.copy()
        clone.overloaded_fields = self.overloaded_fields.copy()
        clone.overload_fields = self.overload_fields.copy()
        clone.underlayer = self.underlayer
        clone.explicit = self.explicit
        clone.raw_packet_cache = self.raw_packet_cache
        clone.post_transforms = self.post_transforms[:]
        clone.__dict__["payload"] = self.payload.copy()
        clone.payload.add_underlayer(clone)
        return clone

    def do_dissect(self, s):
        flist = self.fields_desc[:]
        fld_list = self.fields_desc[:]
        flist.reverse()
        raw = s
        while s and flist:
            f = flist.pop()
            if DLR not in f.owners:
                f.register_owner(DLR);
            print f.name
            s,fval = f.getfield(self,s)
            self.fields[f.name] = fval
            if f.name == 'Frame_Type':
                flist.reverse()
                flist += self.frames[self.fields['Frame_Type']][:]
                fld_list += self.frames[self.fields['Frame_Type']][:]
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
