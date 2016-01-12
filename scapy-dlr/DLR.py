#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Copyright (c) 2015 Yuan Bowei, bernardy@sfu.ca
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
__author__ = 'bernardyuan'
from scapy import all as scapy_all
from scapy import layers as layer
import struct,time
# The field class specially designed for Sign On Info
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
    # parse the MAC addresses and IP addresses from the raw data
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
    # encode the MAC addresses and IP addresses into raw data
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
# The DLR protocol
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
            scapy_all.ByteField('Neighbor_Response_Source_Port',None),
            scapy_all.StrField('Reserved',None)
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
            scapy_all.ByteEnumField('Advertise_Gateway_State',0,{
                0x01:"ACTIVE_LISTEN_STATE",
                0x02:"ACTIVE_NORMAL_STATE",
                0x03:"FAULT_STATE",
                0:None,
            }),
            scapy_all.ByteField('Advertise_Gateway_Precedence',0),
            scapy_all.IntField('Advertise_Interval',0),
            scapy_all.IntField('Advertise_Timeout',0),
            scapy_all.BitEnumField('Learning_Update_Enable',None,1,{
                0: "DISABLED",
                1: "ENABLED",
            }),
            scapy_all.StrField('Reserved',None),
        ],
        9: [
            # Flush Table
            scapy_all.BitEnumField('Learning_Update_Enable',None,1, {
                0: "DISABLED",
                1: "ENABLED",
            }),
            scapy_all.StrField('Reserved',None),
        ],
        10: [
            # Learing Update
            scapy_all.StrField('Reserved',None),
        ],
    }
    # constructor
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
        # add more fields into field_desc according to the value of 'Frame_Type' field
        field_list = self.fields_desc[:]
        if fields and 'Frame_Type' in fields:
            field_list += self.frames[fields['Frame_Type']][:]
            self.fields_desc = field_list[:]
        self.init_fields()
        self.underlayer = _underlayer
        self.initialized = 1
        self.original = _pkt
        # if construct from raw data, dissect the raw data
        if _pkt:
            self.dissect(_pkt)
            if not _internal:
                self.dissection_done(self)
        # if construct from keywords
        if fields:
        # set the explicit value as 1, IMPORTANT for building packet
            self.explicit =1
        # add the values in the keywords in to fields
        for f in fields.keys():
            self.fields[f] = self.get_field(f).any2i(self,fields[f])
        if type(post_transform) is list:
            self.post_transforms = post_transform
        elif post_transform is None:
            self.post_transforms = []
        else:
            self.post_transforms = [post_transform]
        # if built from keywords, initialize the raw_packet_cache as it is build from raw data
        if fields:
            self.raw_packet_cache = self.do_build()
    # made some modifications to the original copy function, deep copy all the fields not only the common fields
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

    # dissect function
    def do_dissect(self, s):
        flist = self.fields_desc[:]
        # save the fields_desc temporarily
        fld_list = self.fields_desc[:]
        flist.reverse()
        raw = s
        while s and flist:
            f = flist.pop()
            if DLR not in f.owners:
                f.register_owner(DLR);
            # print f.name
            s,fval = f.getfield(self,s)
            self.fields[f.name] = fval
            # when we know the frame type, add additional types
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
    def self_build(self, field_pos_list=None):
        # if self.raw_packet_cache is not None:
        #     return self.raw_packet_cache
        p=""
        for f in self.fields_desc:
            val = self.getfieldval(f.name)
            if isinstance(val, scapy_all.RawVal):
                sval = str(val)
                p += sval
                if field_pos_list is not None:
                    field_pos_list.append( (f.name, sval.encode("string_escape"), len(p), len(sval) ) )
            else:
                p = f.addfield(self, p, val)
        return p
scapy_all.bind_layers(layer.l2.Dot1Q, DLR, type=0x80e1)
# scapy_all.bind_layers(DlrBase,DlrBeacon,Frame_Type=1)
