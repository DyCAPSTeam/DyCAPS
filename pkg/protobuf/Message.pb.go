// Code generated by protoc-gen-go. DO NOT EDIT.
// source: Message.proto

/*
Package protobuf is a generated protocol buffer package.

It is generated from these files:
	Message.proto

It has these top-level messages:
	Message
	Value
	Echo
	Lock
	Finish
	Done
	Halt
	PreVote
	Vote
	RBCEcho
	RBCReady
	PiContent
	Pi
	VSSSend
	VSSEcho
	VSSReady
	VSSDistribute
	ShareReduce
	Commit
	Reshare
	Recover
*/
package protobuf

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Message struct {
	Type   string `protobuf:"bytes,1,opt,name=type" json:"type,omitempty"`
	Id     []byte `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Sender uint32 `protobuf:"varint,3,opt,name=sender" json:"sender,omitempty"`
	Data   []byte `protobuf:"bytes,4,opt,name=data,proto3" json:"data,omitempty"`
}

func (m *Message) Reset()                    { *m = Message{} }
func (m *Message) String() string            { return proto.CompactTextString(m) }
func (*Message) ProtoMessage()               {}
func (*Message) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Message) GetType() string {
	if m != nil {
		return m.Type
	}
	return ""
}

func (m *Message) GetId() []byte {
	if m != nil {
		return m.Id
	}
	return nil
}

func (m *Message) GetSender() uint32 {
	if m != nil {
		return m.Sender
	}
	return 0
}

func (m *Message) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

// provable broadcast
type Value struct {
	Value      []byte `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`
	Validation []byte `protobuf:"bytes,2,opt,name=validation,proto3" json:"validation,omitempty"`
}

func (m *Value) Reset()                    { *m = Value{} }
func (m *Value) String() string            { return proto.CompactTextString(m) }
func (*Value) ProtoMessage()               {}
func (*Value) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *Value) GetValue() []byte {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *Value) GetValidation() []byte {
	if m != nil {
		return m.Validation
	}
	return nil
}

type Echo struct {
	Sigshare []byte `protobuf:"bytes,1,opt,name=sigshare,proto3" json:"sigshare,omitempty"`
}

func (m *Echo) Reset()                    { *m = Echo{} }
func (m *Echo) String() string            { return proto.CompactTextString(m) }
func (*Echo) ProtoMessage()               {}
func (*Echo) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *Echo) GetSigshare() []byte {
	if m != nil {
		return m.Sigshare
	}
	return nil
}

// smvba
type Lock struct {
	Value []byte `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`
	Sig   []byte `protobuf:"bytes,2,opt,name=sig,proto3" json:"sig,omitempty"`
}

func (m *Lock) Reset()                    { *m = Lock{} }
func (m *Lock) String() string            { return proto.CompactTextString(m) }
func (*Lock) ProtoMessage()               {}
func (*Lock) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *Lock) GetValue() []byte {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *Lock) GetSig() []byte {
	if m != nil {
		return m.Sig
	}
	return nil
}

type Finish struct {
	Value []byte `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`
	Sig   []byte `protobuf:"bytes,2,opt,name=sig,proto3" json:"sig,omitempty"`
}

func (m *Finish) Reset()                    { *m = Finish{} }
func (m *Finish) String() string            { return proto.CompactTextString(m) }
func (*Finish) ProtoMessage()               {}
func (*Finish) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *Finish) GetValue() []byte {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *Finish) GetSig() []byte {
	if m != nil {
		return m.Sig
	}
	return nil
}

type Done struct {
	CoinShare []byte `protobuf:"bytes,1,opt,name=coinShare,proto3" json:"coinShare,omitempty"`
}

func (m *Done) Reset()                    { *m = Done{} }
func (m *Done) String() string            { return proto.CompactTextString(m) }
func (*Done) ProtoMessage()               {}
func (*Done) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *Done) GetCoinShare() []byte {
	if m != nil {
		return m.CoinShare
	}
	return nil
}

type Halt struct {
	Value []byte `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`
	Sig   []byte `protobuf:"bytes,2,opt,name=sig,proto3" json:"sig,omitempty"`
}

func (m *Halt) Reset()                    { *m = Halt{} }
func (m *Halt) String() string            { return proto.CompactTextString(m) }
func (*Halt) ProtoMessage()               {}
func (*Halt) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *Halt) GetValue() []byte {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *Halt) GetSig() []byte {
	if m != nil {
		return m.Sig
	}
	return nil
}

type PreVote struct {
	Vote  bool   `protobuf:"varint,1,opt,name=vote" json:"vote,omitempty"`
	Value []byte `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	Sig   []byte `protobuf:"bytes,3,opt,name=sig,proto3" json:"sig,omitempty"`
}

func (m *PreVote) Reset()                    { *m = PreVote{} }
func (m *PreVote) String() string            { return proto.CompactTextString(m) }
func (*PreVote) ProtoMessage()               {}
func (*PreVote) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func (m *PreVote) GetVote() bool {
	if m != nil {
		return m.Vote
	}
	return false
}

func (m *PreVote) GetValue() []byte {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *PreVote) GetSig() []byte {
	if m != nil {
		return m.Sig
	}
	return nil
}

type Vote struct {
	Vote     bool   `protobuf:"varint,1,opt,name=vote" json:"vote,omitempty"`
	Value    []byte `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	Sig      []byte `protobuf:"bytes,3,opt,name=sig,proto3" json:"sig,omitempty"`
	Sigshare []byte `protobuf:"bytes,4,opt,name=sigshare,proto3" json:"sigshare,omitempty"`
}

func (m *Vote) Reset()                    { *m = Vote{} }
func (m *Vote) String() string            { return proto.CompactTextString(m) }
func (*Vote) ProtoMessage()               {}
func (*Vote) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{8} }

func (m *Vote) GetVote() bool {
	if m != nil {
		return m.Vote
	}
	return false
}

func (m *Vote) GetValue() []byte {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *Vote) GetSig() []byte {
	if m != nil {
		return m.Sig
	}
	return nil
}

func (m *Vote) GetSigshare() []byte {
	if m != nil {
		return m.Sigshare
	}
	return nil
}

// is this ok?
type RBCEcho struct {
	Hash []byte `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
	M    []byte `protobuf:"bytes,2,opt,name=m,proto3" json:"m,omitempty"`
}

func (m *RBCEcho) Reset()                    { *m = RBCEcho{} }
func (m *RBCEcho) String() string            { return proto.CompactTextString(m) }
func (*RBCEcho) ProtoMessage()               {}
func (*RBCEcho) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{9} }

func (m *RBCEcho) GetHash() []byte {
	if m != nil {
		return m.Hash
	}
	return nil
}

func (m *RBCEcho) GetM() []byte {
	if m != nil {
		return m.M
	}
	return nil
}

type RBCReady struct {
	Hash []byte `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
	M    []byte `protobuf:"bytes,2,opt,name=m,proto3" json:"m,omitempty"`
}

func (m *RBCReady) Reset()                    { *m = RBCReady{} }
func (m *RBCReady) String() string            { return proto.CompactTextString(m) }
func (*RBCReady) ProtoMessage()               {}
func (*RBCReady) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{10} }

func (m *RBCReady) GetHash() []byte {
	if m != nil {
		return m.Hash
	}
	return nil
}

func (m *RBCReady) GetM() []byte {
	if m != nil {
		return m.M
	}
	return nil
}

type PiContent struct {
	J    int32  `protobuf:"varint,1,opt,name=j" json:"j,omitempty"`
	CRJ  []byte `protobuf:"bytes,2,opt,name=CR_j,json=CRJ,proto3" json:"CR_j,omitempty"`
	CZJ  []byte `protobuf:"bytes,3,opt,name=CZ_j,json=CZJ,proto3" json:"CZ_j,omitempty"`
	WZ_0 []byte `protobuf:"bytes,4,opt,name=WZ_0,json=WZ0,proto3" json:"WZ_0,omitempty"`
	G_Fj []byte `protobuf:"bytes,5,opt,name=g_Fj,json=gFj,proto3" json:"g_Fj,omitempty"`
}

func (m *PiContent) Reset()                    { *m = PiContent{} }
func (m *PiContent) String() string            { return proto.CompactTextString(m) }
func (*PiContent) ProtoMessage()               {}
func (*PiContent) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{11} }

func (m *PiContent) GetJ() int32 {
	if m != nil {
		return m.J
	}
	return 0
}

func (m *PiContent) GetCRJ() []byte {
	if m != nil {
		return m.CRJ
	}
	return nil
}

func (m *PiContent) GetCZJ() []byte {
	if m != nil {
		return m.CZJ
	}
	return nil
}

func (m *PiContent) GetWZ_0() []byte {
	if m != nil {
		return m.WZ_0
	}
	return nil
}

func (m *PiContent) GetG_Fj() []byte {
	if m != nil {
		return m.G_Fj
	}
	return nil
}

type Pi struct {
	Gs         []byte       `protobuf:"bytes,1,opt,name=gs,proto3" json:"gs,omitempty"`
	PiContents []*PiContent `protobuf:"bytes,2,rep,name=pi_contents,json=piContents" json:"pi_contents,omitempty"`
}

func (m *Pi) Reset()                    { *m = Pi{} }
func (m *Pi) String() string            { return proto.CompactTextString(m) }
func (*Pi) ProtoMessage()               {}
func (*Pi) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{12} }

func (m *Pi) GetGs() []byte {
	if m != nil {
		return m.Gs
	}
	return nil
}

func (m *Pi) GetPiContents() []*PiContent {
	if m != nil {
		return m.PiContents
	}
	return nil
}

type VSSSend struct {
	Pi       *Pi      `protobuf:"bytes,1,opt,name=pi" json:"pi,omitempty"`
	RjiList  [][]byte `protobuf:"bytes,2,rep,name=Rji_list,json=RjiList,proto3" json:"Rji_list,omitempty"`
	WRjiList [][]byte `protobuf:"bytes,3,rep,name=WRji_list,json=WRjiList,proto3" json:"WRji_list,omitempty"`
}

func (m *VSSSend) Reset()                    { *m = VSSSend{} }
func (m *VSSSend) String() string            { return proto.CompactTextString(m) }
func (*VSSSend) ProtoMessage()               {}
func (*VSSSend) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{13} }

func (m *VSSSend) GetPi() *Pi {
	if m != nil {
		return m.Pi
	}
	return nil
}

func (m *VSSSend) GetRjiList() [][]byte {
	if m != nil {
		return m.RjiList
	}
	return nil
}

func (m *VSSSend) GetWRjiList() [][]byte {
	if m != nil {
		return m.WRjiList
	}
	return nil
}

type VSSEcho struct {
	Pi *Pi `protobuf:"bytes,1,opt,name=pi" json:"pi,omitempty"`
}

func (m *VSSEcho) Reset()                    { *m = VSSEcho{} }
func (m *VSSEcho) String() string            { return proto.CompactTextString(m) }
func (*VSSEcho) ProtoMessage()               {}
func (*VSSEcho) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{14} }

func (m *VSSEcho) GetPi() *Pi {
	if m != nil {
		return m.Pi
	}
	return nil
}

type VSSReady struct {
	Pi        *Pi    `protobuf:"bytes,1,opt,name=pi" json:"pi,omitempty"`
	ReadyType string `protobuf:"bytes,2,opt,name=ReadyType" json:"ReadyType,omitempty"`
	BIl       []byte `protobuf:"bytes,3,opt,name=B_il,json=BIl,proto3" json:"B_il,omitempty"`
	WBIl      []byte `protobuf:"bytes,4,opt,name=WB_il,json=WBIl,proto3" json:"WB_il,omitempty"`
}

func (m *VSSReady) Reset()                    { *m = VSSReady{} }
func (m *VSSReady) String() string            { return proto.CompactTextString(m) }
func (*VSSReady) ProtoMessage()               {}
func (*VSSReady) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{15} }

func (m *VSSReady) GetPi() *Pi {
	if m != nil {
		return m.Pi
	}
	return nil
}

func (m *VSSReady) GetReadyType() string {
	if m != nil {
		return m.ReadyType
	}
	return ""
}

func (m *VSSReady) GetBIl() []byte {
	if m != nil {
		return m.BIl
	}
	return nil
}

func (m *VSSReady) GetWBIl() []byte {
	if m != nil {
		return m.WBIl
	}
	return nil
}

type VSSDistribute struct {
	BLi  []byte `protobuf:"bytes,1,opt,name=B_li,json=BLi,proto3" json:"B_li,omitempty"`
	WBLi []byte `protobuf:"bytes,2,opt,name=WB_li,json=WBLi,proto3" json:"WB_li,omitempty"`
}

func (m *VSSDistribute) Reset()                    { *m = VSSDistribute{} }
func (m *VSSDistribute) String() string            { return proto.CompactTextString(m) }
func (*VSSDistribute) ProtoMessage()               {}
func (*VSSDistribute) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{16} }

func (m *VSSDistribute) GetBLi() []byte {
	if m != nil {
		return m.BLi
	}
	return nil
}

func (m *VSSDistribute) GetWBLi() []byte {
	if m != nil {
		return m.WBLi
	}
	return nil
}

type ShareReduce struct {
	C []byte `protobuf:"bytes,1,opt,name=C,proto3" json:"C,omitempty"`
	V []byte `protobuf:"bytes,2,opt,name=v,proto3" json:"v,omitempty"`
	W []byte `protobuf:"bytes,3,opt,name=W,proto3" json:"W,omitempty"`
}

func (m *ShareReduce) Reset()                    { *m = ShareReduce{} }
func (m *ShareReduce) String() string            { return proto.CompactTextString(m) }
func (*ShareReduce) ProtoMessage()               {}
func (*ShareReduce) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{17} }

func (m *ShareReduce) GetC() []byte {
	if m != nil {
		return m.C
	}
	return nil
}

func (m *ShareReduce) GetV() []byte {
	if m != nil {
		return m.V
	}
	return nil
}

func (m *ShareReduce) GetW() []byte {
	if m != nil {
		return m.W
	}
	return nil
}

type Commit struct {
	Sig []*PiContent `protobuf:"bytes,1,rep,name=Sig" json:"Sig,omitempty"`
}

func (m *Commit) Reset()                    { *m = Commit{} }
func (m *Commit) String() string            { return proto.CompactTextString(m) }
func (*Commit) ProtoMessage()               {}
func (*Commit) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{18} }

func (m *Commit) GetSig() []*PiContent {
	if m != nil {
		return m.Sig
	}
	return nil
}

type Reshare struct {
	Fk [][]byte `protobuf:"bytes,1,rep,name=Fk,proto3" json:"Fk,omitempty"`
	Wk [][]byte `protobuf:"bytes,2,rep,name=wk,proto3" json:"wk,omitempty"`
}

func (m *Reshare) Reset()                    { *m = Reshare{} }
func (m *Reshare) String() string            { return proto.CompactTextString(m) }
func (*Reshare) ProtoMessage()               {}
func (*Reshare) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{19} }

func (m *Reshare) GetFk() [][]byte {
	if m != nil {
		return m.Fk
	}
	return nil
}

func (m *Reshare) GetWk() [][]byte {
	if m != nil {
		return m.Wk
	}
	return nil
}

type Recover struct {
	J   int32  `protobuf:"varint,1,opt,name=j" json:"j,omitempty"`
	V   []byte `protobuf:"bytes,2,opt,name=v,proto3" json:"v,omitempty"`
	W   []byte `protobuf:"bytes,3,opt,name=w,proto3" json:"w,omitempty"`
	Sig []byte `protobuf:"bytes,4,opt,name=sig,proto3" json:"sig,omitempty"`
}

func (m *Recover) Reset()                    { *m = Recover{} }
func (m *Recover) String() string            { return proto.CompactTextString(m) }
func (*Recover) ProtoMessage()               {}
func (*Recover) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{20} }

func (m *Recover) GetJ() int32 {
	if m != nil {
		return m.J
	}
	return 0
}

func (m *Recover) GetV() []byte {
	if m != nil {
		return m.V
	}
	return nil
}

func (m *Recover) GetW() []byte {
	if m != nil {
		return m.W
	}
	return nil
}

func (m *Recover) GetSig() []byte {
	if m != nil {
		return m.Sig
	}
	return nil
}

func init() {
	proto.RegisterType((*Message)(nil), "Message")
	proto.RegisterType((*Value)(nil), "Value")
	proto.RegisterType((*Echo)(nil), "Echo")
	proto.RegisterType((*Lock)(nil), "Lock")
	proto.RegisterType((*Finish)(nil), "Finish")
	proto.RegisterType((*Done)(nil), "Done")
	proto.RegisterType((*Halt)(nil), "Halt")
	proto.RegisterType((*PreVote)(nil), "PreVote")
	proto.RegisterType((*Vote)(nil), "Vote")
	proto.RegisterType((*RBCEcho)(nil), "RBCEcho")
	proto.RegisterType((*RBCReady)(nil), "RBCReady")
	proto.RegisterType((*PiContent)(nil), "Pi_content")
	proto.RegisterType((*Pi)(nil), "Pi")
	proto.RegisterType((*VSSSend)(nil), "VSSSend")
	proto.RegisterType((*VSSEcho)(nil), "VSSEcho")
	proto.RegisterType((*VSSReady)(nil), "VSSReady")
	proto.RegisterType((*VSSDistribute)(nil), "VSSDistribute")
	proto.RegisterType((*ShareReduce)(nil), "ShareReduce")
	proto.RegisterType((*Commit)(nil), "Commit")
	proto.RegisterType((*Reshare)(nil), "Reshare")
	proto.RegisterType((*Recover)(nil), "Recover")
}

func init() { proto.RegisterFile("Message.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 636 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x54, 0xdf, 0x6b, 0x13, 0x41,
	0x10, 0xe6, 0x7e, 0xe4, 0xd7, 0x24, 0x15, 0xdd, 0x8a, 0x44, 0xad, 0x25, 0x2c, 0x82, 0x11, 0x4b,
	0x2c, 0xf5, 0xa1, 0x4f, 0xbe, 0xdc, 0xb5, 0xc1, 0x4a, 0x84, 0xb0, 0x27, 0x39, 0xcc, 0x83, 0xe1,
	0x9a, 0xdb, 0x5e, 0xe6, 0x72, 0xb9, 0x0b, 0xd9, 0x4d, 0x42, 0xff, 0x7b, 0xd9, 0xcd, 0x26, 0xa9,
	0x6d, 0x85, 0x82, 0x6f, 0x33, 0xdf, 0xec, 0x7c, 0xfb, 0xdd, 0x37, 0x3b, 0x07, 0x07, 0x3f, 0xb8,
	0x10, 0x51, 0xc2, 0x3b, 0xf3, 0x45, 0x21, 0x0b, 0xfa, 0x0b, 0x2a, 0x06, 0x20, 0x04, 0x5c, 0x79,
	0x3b, 0xe7, 0x4d, 0xab, 0x65, 0xb5, 0x6b, 0x4c, 0xc7, 0xe4, 0x19, 0xd8, 0x18, 0x37, 0xed, 0x96,
	0xd5, 0x6e, 0x30, 0x1b, 0x63, 0xf2, 0x0a, 0xca, 0x82, 0xe7, 0x31, 0x5f, 0x34, 0x9d, 0x96, 0xd5,
	0x3e, 0x60, 0x26, 0x53, 0xbd, 0x71, 0x24, 0xa3, 0xa6, 0xab, 0x4f, 0xea, 0x98, 0x7e, 0x85, 0xd2,
	0x20, 0xca, 0x96, 0x9c, 0xbc, 0x84, 0xd2, 0x4a, 0x05, 0x9a, 0xb9, 0xc1, 0x36, 0x09, 0x39, 0x06,
	0x58, 0x45, 0x19, 0xc6, 0x91, 0xc4, 0x22, 0x37, 0x57, 0xdc, 0x41, 0x28, 0x05, 0xf7, 0x72, 0x3c,
	0x29, 0xc8, 0x1b, 0xa8, 0x0a, 0x4c, 0xc4, 0x24, 0x5a, 0x6c, 0x09, 0x76, 0x39, 0xed, 0x80, 0xdb,
	0x2b, 0xc6, 0xd3, 0x7f, 0xdc, 0xf0, 0x1c, 0x1c, 0x81, 0x89, 0xa1, 0x56, 0x21, 0x3d, 0x85, 0x72,
	0x17, 0x73, 0x14, 0x93, 0x27, 0x77, 0xbc, 0x07, 0xf7, 0xa2, 0xc8, 0x39, 0x39, 0x82, 0xda, 0xb8,
	0xc0, 0x3c, 0xb8, 0x23, 0x63, 0x0f, 0x28, 0x1d, 0xdf, 0xa2, 0x4c, 0x3e, 0x99, 0xf5, 0x12, 0x2a,
	0xfd, 0x05, 0x1f, 0x14, 0x52, 0xbb, 0xbe, 0x2a, 0xe4, 0xa6, 0xa3, 0xca, 0x74, 0xbc, 0xa7, 0xb1,
	0x1f, 0xa1, 0x71, 0xf6, 0x34, 0xbf, 0xc1, 0xfd, 0x5f, 0x8e, 0xbf, 0xec, 0x75, 0xef, 0xd9, 0xfb,
	0x09, 0x2a, 0xcc, 0xf3, 0xf5, 0x14, 0x08, 0xb8, 0x93, 0x48, 0x4c, 0xcc, 0x87, 0xe9, 0x98, 0x34,
	0xc0, 0x9a, 0x19, 0x7a, 0x6b, 0x46, 0x4f, 0xa0, 0xca, 0x3c, 0x9f, 0xf1, 0x28, 0xbe, 0x7d, 0xc2,
	0xe9, 0x1b, 0x80, 0x3e, 0x8e, 0xc6, 0x45, 0x2e, 0x79, 0x2e, 0x55, 0x2d, 0xd5, 0x87, 0x4b, 0xcc,
	0x4a, 0xc9, 0x0b, 0x70, 0x7d, 0x36, 0x4a, 0xb7, 0x86, 0xf9, 0xec, 0xbb, 0x86, 0x86, 0xa3, 0x74,
	0x2b, 0xdc, 0x1f, 0x6a, 0x28, 0x1c, 0x8e, 0x4e, 0x8d, 0x68, 0x27, 0x1c, 0x9e, 0x2a, 0x28, 0x19,
	0x75, 0xd3, 0x66, 0x69, 0x03, 0x25, 0xdd, 0x94, 0x7a, 0x60, 0xf7, 0x51, 0x3d, 0xe3, 0x44, 0x18,
	0x35, 0x76, 0x22, 0xc8, 0x09, 0xd4, 0xe7, 0xbb, 0xdb, 0x45, 0xd3, 0x6e, 0x39, 0xed, 0xfa, 0x59,
	0xbd, 0xb3, 0x57, 0xc4, 0x60, 0x8e, 0xbe, 0x29, 0xd3, 0x01, 0x54, 0x06, 0x41, 0x10, 0xf0, 0x3c,
	0x26, 0x87, 0x60, 0xcf, 0x51, 0x13, 0xd5, 0xcf, 0x9c, 0x4e, 0x1f, 0x99, 0x3d, 0x47, 0xf2, 0x1a,
	0xaa, 0x2c, 0xc5, 0x51, 0x86, 0x42, 0x6a, 0xaa, 0x06, 0xab, 0xb0, 0x14, 0x7b, 0x28, 0x24, 0x79,
	0x0b, 0xb5, 0x70, 0x57, 0x73, 0x74, 0xad, 0x1a, 0x9a, 0x22, 0x3d, 0xd6, 0xbc, 0xda, 0xde, 0xc7,
	0x78, 0x29, 0x87, 0xea, 0x20, 0x08, 0x36, 0x8e, 0x3e, 0x7a, 0xf1, 0x11, 0xd4, 0x74, 0xf5, 0xa7,
	0x5a, 0x5b, 0x5b, 0xaf, 0xed, 0x1e, 0x50, 0x6e, 0x78, 0x23, 0xcc, 0xb6, 0x9e, 0x79, 0x57, 0x19,
	0x39, 0x84, 0x52, 0xa8, 0x31, 0xb3, 0xa7, 0xa1, 0x77, 0x95, 0xd1, 0x73, 0x38, 0x18, 0x04, 0xc1,
	0x05, 0x0a, 0xb9, 0xc0, 0xeb, 0xa5, 0x34, 0x8d, 0x19, 0x1a, 0xbf, 0x1c, 0xaf, 0x87, 0xa6, 0x31,
	0x43, 0x33, 0x13, 0x37, 0xf4, 0x7a, 0x48, 0xcf, 0xa1, 0xae, 0x9f, 0x3f, 0xe3, 0xf1, 0x72, 0xcc,
	0xd5, 0x10, 0x7d, 0xd3, 0x63, 0xf9, 0x2a, 0x5b, 0x6d, 0xc7, 0xbd, 0x52, 0x59, 0x68, 0x84, 0x58,
	0x21, 0xfd, 0x00, 0x65, 0xbf, 0x98, 0xcd, 0x50, 0x92, 0x77, 0xe0, 0x04, 0x98, 0x34, 0xad, 0x87,
	0x03, 0x50, 0x38, 0xfd, 0x08, 0x15, 0xc6, 0xf5, 0x5b, 0x54, 0x23, 0xec, 0x4e, 0xf5, 0xc1, 0x06,
	0xb3, 0xbb, 0x53, 0x95, 0xaf, 0xa7, 0xc6, 0x6e, 0x7b, 0x3d, 0x55, 0x2b, 0xc5, 0xf8, 0xb8, 0x58,
	0xf1, 0xc5, 0xbd, 0xd7, 0xf4, 0x40, 0xc8, 0x7a, 0x2b, 0x64, 0xbd, 0x5d, 0x07, 0x77, 0xb7, 0x0e,
	0x5e, 0x7d, 0x58, 0xfb, 0xac, 0xff, 0x8c, 0xd7, 0xcb, 0x9b, 0xeb, 0xb2, 0x8e, 0xbe, 0xfc, 0x09,
	0x00, 0x00, 0xff, 0xff, 0x9c, 0xd2, 0x97, 0x9b, 0x34, 0x05, 0x00, 0x00,
}
