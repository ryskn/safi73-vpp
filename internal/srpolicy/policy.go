// Package srpolicy は RFC 9256 の SR Policy アーキテクチャを、制御プレーン(gobgp)・
// データプレーン(VPP)の実装詳細に依存しない形で表すドメイン層。
//
// 用語(RFC 9256):
//   - SR Policy        : <color, endpoint> で識別 (headend は自ノードなので含めない)
//   - Candidate Path   : SR Policy の候補。<protocol-origin, originator, discriminator> で識別
//   - Segment List     : candidate path 内の SID 列。weight 付き(weighted ECMP)
//   - active CP        : 妥当な CP の中から §2.9 の規則で選ばれた 1 本。これのみ instantiate
package srpolicy

import (
	"bytes"
	"fmt"
	"net/netip"
)

// SegmentList は candidate path 1 本分の SID 列と重み。
type SegmentList struct {
	Weight uint32
	SIDs   []netip.Addr
}

// Valid は RFC 9256 §5.1 に従い SID-list の妥当性を返す。
// 空 / weight==0 / 非 IPv6(SRv6でない) SID を含む場合は invalid。
func (sl SegmentList) Valid() bool {
	if len(sl.SIDs) == 0 || sl.Weight == 0 {
		return false
	}
	for _, s := range sl.SIDs {
		if !s.Is6() || s.Is4In6() {
			return false
		}
	}
	return true
}

// ProtocolOrigin は CP を導入したプロトコル種別(RFC 9256 §2.9, 値が大きいほど優先)。
type ProtocolOrigin uint8

const (
	OriginPCEP   ProtocolOrigin = 10
	OriginBGP    ProtocolOrigin = 20
	OriginConfig ProtocolOrigin = 30
)

// Originator は 160bit(4byte ASN + 128bit node)。RFC 9256 のタイブレーク用。
type Originator struct {
	ASN  uint32
	Node netip.Addr
}

func (o Originator) key() [20]byte {
	var b [20]byte
	b[0], b[1], b[2], b[3] = byte(o.ASN>>24), byte(o.ASN>>16), byte(o.ASN>>8), byte(o.ASN)
	n := o.Node.As16()
	copy(b[4:], n[:])
	return b
}

// Compare は o<other:-1, o==other:0, o>other:+1 を返す。
func (o Originator) Compare(other Originator) int {
	a, b := o.key(), other.key()
	return bytes.Compare(a[:], b[:])
}

// PolicyKey は SR Policy の識別子 <color, endpoint>。
type PolicyKey struct {
	Color    uint32
	Endpoint netip.Addr
}

func (k PolicyKey) String() string {
	return fmt.Sprintf("color=%d,endpoint=%s", k.Color, k.Endpoint)
}

// CPKey は candidate path の一意キー <protocol-origin, originator, discriminator>。
type CPKey struct {
	Origin        ProtocolOrigin
	OriginatorASN uint32
	OriginatorNode netip.Addr
	Discriminator uint32
}

// CandidatePath は SR Policy の候補パス 1 本(BGP の 1 NLRI+attrs に対応)。
type CandidatePath struct {
	Origin        ProtocolOrigin
	Originator    Originator
	Discriminator uint32

	Preference   uint32
	Priority     uint32
	BSID         netip.Addr
	SegmentLists []SegmentList
}

// Key は candidate path の一意キーを返す。
func (cp CandidatePath) Key() CPKey {
	return CPKey{cp.Origin, cp.Originator.ASN, cp.Originator.Node, cp.Discriminator}
}

// Valid は RFC 9256 に従い CP の妥当性を返す。
// BSID が SRv6(IPv6) かつ valid な SID-list を 1 本以上持てば valid。
func (cp CandidatePath) Valid() bool {
	if !cp.BSID.Is6() || cp.BSID.Is4In6() {
		return false
	}
	for _, sl := range cp.SegmentLists {
		if sl.Valid() {
			return true
		}
	}
	return false
}

// ValidSegmentLists は weight==0/空などを除いた、転送に使う SID-list を返す。
func (cp CandidatePath) ValidSegmentLists() []SegmentList {
	out := make([]SegmentList, 0, len(cp.SegmentLists))
	for _, sl := range cp.SegmentLists {
		if sl.Valid() {
			out = append(out, sl)
		}
	}
	return out
}
