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

// DefaultPreference は Preference sub-TLV 不在時の既定値(RFC 9256 §2.7)。
const DefaultPreference = 100

// MaxSIDsPerList はこの headend が instantiate できる SID 数の上限。
// VPP binary API の srv6_sid_list が 16 固定のため。超過は RFC 9256 §5.1 の
// 「headend が解決できない SID-list」として invalid 扱いにする(切り詰め禁止)。
const MaxSIDsPerList = 16

// SegmentList は candidate path 1 本分の SID 列と重み。
type SegmentList struct {
	Weight uint32
	SIDs   []netip.Addr
	// Unsupported は SRv6 以外(SR-MPLS 等)の segment type を含んでいたことを示す。
	// RFC 9256 §5.1: SR-MPLS と SRv6 の混在 list は invalid(部分的に使うのは禁止)。
	Unsupported bool
}

// Valid は RFC 9256 §5.1 に従い SID-list の妥当性を返す。
// 空 / weight==0 / 非 IPv6(SRv6でない) SID / 混在 segment type /
// headend 上限(MaxSIDsPerList)超過は invalid。
func (sl SegmentList) Valid() bool {
	if sl.Unsupported || len(sl.SIDs) == 0 || len(sl.SIDs) > MaxSIDsPerList || sl.Weight == 0 {
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
	Origin         ProtocolOrigin
	OriginatorASN  uint32
	OriginatorNode netip.Addr
	Discriminator  uint32
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

	// SpecifiedBSIDOnly は BSID sub-TLV の S-Flag(RFC 9256 §6.2.3)。
	// 立っていると BSID 未指定/割当不可のとき CP を invalid にする(動的割当を許さない)。
	SpecifiedBSIDOnly bool
	// DropUponInvalid は BSID sub-TLV の I-Flag(RFC 9256 §8.2)。
	// VPP dataplane に相当機能が無いため未対応(検出してログのみ)。
	DropUponInvalid bool
}

// Key は candidate path の一意キーを返す。
func (cp CandidatePath) Key() CPKey {
	return CPKey{cp.Origin, cp.Originator.ASN, cp.Originator.Node, cp.Discriminator}
}

// HasBSID は SRv6 として使える BSID が指定されているかを返す。
func (cp CandidatePath) HasBSID() bool {
	return cp.BSID.IsValid() && cp.BSID.Is6() && !cp.BSID.Is4In6()
}

// Valid は RFC 9256 に従い CP の妥当性を返す。
// valid な SID-list を 1 本以上持てば valid。BSID は無くてもよく(§6.2.1 の動的割当対象)、
// 割当可否(プール設定の有無)は headend 側 = Reconciler が判定する。ただし
//   - BSID が指定されているのに SRv6(IPv6) でない → invalid
//   - S-Flag(Specified-BSID-only, §6.2.3)付きで BSID 未指定 → invalid
func (cp CandidatePath) Valid() bool {
	if cp.BSID.IsValid() && (!cp.BSID.Is6() || cp.BSID.Is4In6()) {
		return false
	}
	if !cp.HasBSID() && cp.SpecifiedBSIDOnly {
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
