// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: proto/crypto/keys/types.proto

package keys

import (
	bytes "bytes"
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// PublicKey defines the keys available for use with Tendermint Validators
type PublicKey struct {
	// Types that are valid to be assigned to Sum:
	//	*PublicKey_Ed25519
	//	*PublicKey_Bls12_381
	Sum                  isPublicKey_Sum `protobuf_oneof:"sum"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *PublicKey) Reset()         { *m = PublicKey{} }
func (m *PublicKey) String() string { return proto.CompactTextString(m) }
func (*PublicKey) ProtoMessage()    {}
func (*PublicKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_943d79b57ec0188f, []int{0}
}
func (m *PublicKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PublicKey.Unmarshal(m, b)
}
func (m *PublicKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PublicKey.Marshal(b, m, deterministic)
}
func (m *PublicKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PublicKey.Merge(m, src)
}
func (m *PublicKey) XXX_Size() int {
	return xxx_messageInfo_PublicKey.Size(m)
}
func (m *PublicKey) XXX_DiscardUnknown() {
	xxx_messageInfo_PublicKey.DiscardUnknown(m)
}

var xxx_messageInfo_PublicKey proto.InternalMessageInfo

type isPublicKey_Sum interface {
	isPublicKey_Sum()
	Equal(interface{}) bool
	Compare(interface{}) int
}

type PublicKey_Ed25519 struct {
	Ed25519 []byte `protobuf:"bytes,1,opt,name=ed25519,proto3,oneof" json:"ed25519,omitempty"`
}
type PublicKey_Bls12_381 struct {
	Bls12_381 []byte `protobuf:"bytes,2,opt,name=bls12_381,json=bls12381,proto3,oneof" json:"bls12_381,omitempty"`
}

func (*PublicKey_Ed25519) isPublicKey_Sum()   {}
func (*PublicKey_Bls12_381) isPublicKey_Sum() {}

func (m *PublicKey) GetSum() isPublicKey_Sum {
	if m != nil {
		return m.Sum
	}
	return nil
}

func (m *PublicKey) GetEd25519() []byte {
	if x, ok := m.GetSum().(*PublicKey_Ed25519); ok {
		return x.Ed25519
	}
	return nil
}

func (m *PublicKey) GetBls12_381() []byte {
	if x, ok := m.GetSum().(*PublicKey_Bls12_381); ok {
		return x.Bls12_381
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*PublicKey) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*PublicKey_Ed25519)(nil),
		(*PublicKey_Bls12_381)(nil),
	}
}

// PrivateKey defines the keys available for use with Tendermint Validators
// WARNING PrivateKey is used for internal purposes only
type PrivateKey struct {
	// Types that are valid to be assigned to Sum:
	//	*PrivateKey_Ed25519
	//	*PrivateKey_Bls12_381
	Sum                  isPrivateKey_Sum `protobuf_oneof:"sum"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *PrivateKey) Reset()         { *m = PrivateKey{} }
func (m *PrivateKey) String() string { return proto.CompactTextString(m) }
func (*PrivateKey) ProtoMessage()    {}
func (*PrivateKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_943d79b57ec0188f, []int{1}
}
func (m *PrivateKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PrivateKey.Unmarshal(m, b)
}
func (m *PrivateKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PrivateKey.Marshal(b, m, deterministic)
}
func (m *PrivateKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PrivateKey.Merge(m, src)
}
func (m *PrivateKey) XXX_Size() int {
	return xxx_messageInfo_PrivateKey.Size(m)
}
func (m *PrivateKey) XXX_DiscardUnknown() {
	xxx_messageInfo_PrivateKey.DiscardUnknown(m)
}

var xxx_messageInfo_PrivateKey proto.InternalMessageInfo

type isPrivateKey_Sum interface {
	isPrivateKey_Sum()
}

type PrivateKey_Ed25519 struct {
	Ed25519 []byte `protobuf:"bytes,1,opt,name=ed25519,proto3,oneof" json:"ed25519,omitempty"`
}
type PrivateKey_Bls12_381 struct {
	Bls12_381 []byte `protobuf:"bytes,2,opt,name=bls12_381,json=bls12381,proto3,oneof" json:"bls12_381,omitempty"`
}

func (*PrivateKey_Ed25519) isPrivateKey_Sum()   {}
func (*PrivateKey_Bls12_381) isPrivateKey_Sum() {}

func (m *PrivateKey) GetSum() isPrivateKey_Sum {
	if m != nil {
		return m.Sum
	}
	return nil
}

func (m *PrivateKey) GetEd25519() []byte {
	if x, ok := m.GetSum().(*PrivateKey_Ed25519); ok {
		return x.Ed25519
	}
	return nil
}

func (m *PrivateKey) GetBls12_381() []byte {
	if x, ok := m.GetSum().(*PrivateKey_Bls12_381); ok {
		return x.Bls12_381
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*PrivateKey) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*PrivateKey_Ed25519)(nil),
		(*PrivateKey_Bls12_381)(nil),
	}
}

func init() {
	proto.RegisterType((*PublicKey)(nil), "tendermint.proto.crypto.keys.PublicKey")
	proto.RegisterType((*PrivateKey)(nil), "tendermint.proto.crypto.keys.PrivateKey")
}

func init() { proto.RegisterFile("proto/crypto/keys/types.proto", fileDescriptor_943d79b57ec0188f) }

var fileDescriptor_943d79b57ec0188f = []byte{
	// 213 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x92, 0x2d, 0x28, 0xca, 0x2f,
	0xc9, 0xd7, 0x4f, 0x2e, 0xaa, 0x2c, 0x28, 0xc9, 0xd7, 0xcf, 0x4e, 0xad, 0x2c, 0xd6, 0x2f, 0xa9,
	0x2c, 0x48, 0x2d, 0xd6, 0x03, 0x8b, 0x0b, 0xc9, 0x94, 0xa4, 0xe6, 0xa5, 0xa4, 0x16, 0xe5, 0x66,
	0xe6, 0x95, 0x40, 0x44, 0xf4, 0x20, 0x2a, 0xf5, 0x40, 0x2a, 0xa5, 0xd4, 0x4a, 0x32, 0x32, 0x8b,
	0x52, 0xe2, 0x0b, 0x12, 0x8b, 0x4a, 0x2a, 0xf5, 0x21, 0x06, 0xa5, 0xe7, 0xa7, 0xe7, 0x23, 0x58,
	0x10, 0x3d, 0x4a, 0xe1, 0x5c, 0x9c, 0x01, 0xa5, 0x49, 0x39, 0x99, 0xc9, 0xde, 0xa9, 0x95, 0x42,
	0x52, 0x5c, 0xec, 0xa9, 0x29, 0x46, 0xa6, 0xa6, 0x86, 0x96, 0x12, 0x8c, 0x0a, 0x8c, 0x1a, 0x3c,
	0x1e, 0x0c, 0x41, 0x30, 0x01, 0x21, 0x59, 0x2e, 0xce, 0xa4, 0x9c, 0x62, 0x43, 0xa3, 0x78, 0x63,
	0x0b, 0x43, 0x09, 0x26, 0xa8, 0x2c, 0x07, 0x58, 0xc8, 0xd8, 0xc2, 0xd0, 0x8a, 0xe3, 0xc5, 0x02,
	0x79, 0xc6, 0x17, 0x0b, 0xe5, 0x19, 0x9d, 0x58, 0xb9, 0x98, 0x8b, 0x4b, 0x73, 0x95, 0xfc, 0xb8,
	0xb8, 0x02, 0x8a, 0x32, 0xcb, 0x12, 0x4b, 0x52, 0x29, 0x33, 0x19, 0x6a, 0x9e, 0x93, 0x49, 0x94,
	0x51, 0x7a, 0x66, 0x49, 0x46, 0x69, 0x92, 0x5e, 0x72, 0x7e, 0xae, 0x3e, 0xc2, 0xef, 0xc8, 0x4c,
	0x8c, 0x00, 0x4b, 0x62, 0x03, 0x0b, 0x19, 0x03, 0x02, 0x00, 0x00, 0xff, 0xff, 0xfc, 0x31, 0x25,
	0xba, 0x4c, 0x01, 0x00, 0x00,
}

func (this *PublicKey) Compare(that interface{}) int {
	if that == nil {
		if this == nil {
			return 0
		}
		return 1
	}

	that1, ok := that.(*PublicKey)
	if !ok {
		that2, ok := that.(PublicKey)
		if ok {
			that1 = &that2
		} else {
			return 1
		}
	}
	if that1 == nil {
		if this == nil {
			return 0
		}
		return 1
	} else if this == nil {
		return -1
	}
	if that1.Sum == nil {
		if this.Sum != nil {
			return 1
		}
	} else if this.Sum == nil {
		return -1
	} else {
		thisType := -1
		switch this.Sum.(type) {
		case *PublicKey_Ed25519:
			thisType = 0
		case *PublicKey_Bls12_381:
			thisType = 1
		default:
			panic(fmt.Sprintf("compare: unexpected type %T in oneof", this.Sum))
		}
		that1Type := -1
		switch that1.Sum.(type) {
		case *PublicKey_Ed25519:
			that1Type = 0
		case *PublicKey_Bls12_381:
			that1Type = 1
		default:
			panic(fmt.Sprintf("compare: unexpected type %T in oneof", that1.Sum))
		}
		if thisType == that1Type {
			if c := this.Sum.Compare(that1.Sum); c != 0 {
				return c
			}
		} else if thisType < that1Type {
			return -1
		} else if thisType > that1Type {
			return 1
		}
	}
	if c := bytes.Compare(this.XXX_unrecognized, that1.XXX_unrecognized); c != 0 {
		return c
	}
	return 0
}
func (this *PublicKey_Ed25519) Compare(that interface{}) int {
	if that == nil {
		if this == nil {
			return 0
		}
		return 1
	}

	that1, ok := that.(*PublicKey_Ed25519)
	if !ok {
		that2, ok := that.(PublicKey_Ed25519)
		if ok {
			that1 = &that2
		} else {
			return 1
		}
	}
	if that1 == nil {
		if this == nil {
			return 0
		}
		return 1
	} else if this == nil {
		return -1
	}
	if c := bytes.Compare(this.Ed25519, that1.Ed25519); c != 0 {
		return c
	}
	return 0
}
func (this *PublicKey_Bls12_381) Compare(that interface{}) int {
	if that == nil {
		if this == nil {
			return 0
		}
		return 1
	}

	that1, ok := that.(*PublicKey_Bls12_381)
	if !ok {
		that2, ok := that.(PublicKey_Bls12_381)
		if ok {
			that1 = &that2
		} else {
			return 1
		}
	}
	if that1 == nil {
		if this == nil {
			return 0
		}
		return 1
	} else if this == nil {
		return -1
	}
	if c := bytes.Compare(this.Bls12_381, that1.Bls12_381); c != 0 {
		return c
	}
	return 0
}
func (this *PublicKey) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*PublicKey)
	if !ok {
		that2, ok := that.(PublicKey)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if that1.Sum == nil {
		if this.Sum != nil {
			return false
		}
	} else if this.Sum == nil {
		return false
	} else if !this.Sum.Equal(that1.Sum) {
		return false
	}
	if !bytes.Equal(this.XXX_unrecognized, that1.XXX_unrecognized) {
		return false
	}
	return true
}
func (this *PublicKey_Ed25519) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*PublicKey_Ed25519)
	if !ok {
		that2, ok := that.(PublicKey_Ed25519)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if !bytes.Equal(this.Ed25519, that1.Ed25519) {
		return false
	}
	return true
}
func (this *PublicKey_Bls12_381) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*PublicKey_Bls12_381)
	if !ok {
		that2, ok := that.(PublicKey_Bls12_381)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if !bytes.Equal(this.Bls12_381, that1.Bls12_381) {
		return false
	}
	return true
}
