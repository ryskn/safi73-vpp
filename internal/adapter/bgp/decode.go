package bgp

import (
	"fmt"
	"net/netip"
	"slices"

	api "github.com/osrg/gobgp/v4/api"

	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

const (
	// tunnelTypeSRPolicy は Tunnel Encapsulation attribute の SR Policy tunnel type
	// (RFC 9830 §2.2, code point 15)。他 tunnel type の TLV は読まない。
	tunnelTypeSRPolicy = 15
	// subTLVSRv6BSID は SRv6 Binding SID sub-TLV (RFC 9830 §2.4.3, type 20)。
	// gobgp v4.5 は wire の type 20 をパースせず Unknown として渡すため自前で読む。
	subTLVSRv6BSID = 20
	// noAdvertise は well-known NO_ADVERTISE community (RFC 1997)。
	noAdvertise = 0xFFFFFF02
	// IPv4-address-specific extended community の sub-type (RFC 4360)。
	extSubTypeRouteTarget = 0x02
	extSubTypeRouteOrigin = 0x03
)

// decodePath は gobgp の api.Path を srpolicy.Event(= 1 candidate path の更新)に変換する。
// SR Policy (SAFI 73) でなければ ok=false。
//
// localID は受信ノードの BGP Identifier。RFC 9830 §4.2 の受信規則を適用し、
// 使用不可(not usable / malformed)と判定した update は Withdraw イベントに落とす
// (§4.2.2: unusable になった CP は SRPM から削除しなければならない)。
// その場合 note に理由を返す(呼び出し側でログする)。
//
// SR Policy(<color,endpoint>)とその candidate path 識別子は次のように対応付ける:
//   - color / endpoint     <- NLRI
//   - protocol-origin      <- BGP(20) 固定
//   - originator ASN       <- 経路の source ASN
//   - originator node      <- Route Origin community > ORIGINATOR_ID > peer router-id
//     (RFC 9830 §2.1 の導出優先順)
//   - discriminator        <- NLRI の distinguisher (RFC 9830 §2.1)
func decodePath(p *api.Path, localID netip.Addr) (ev srpolicy.Event, ok bool, note string) {
	if p.GetFamily().GetSafi() != api.Family_SAFI_SR_POLICY {
		return srpolicy.Event{}, false, ""
	}
	nlri := p.GetNlri().GetSrPolicy()
	if nlri == nil {
		return srpolicy.Event{}, false, ""
	}
	endpoint, _ := netip.AddrFromSlice(nlri.GetEndpoint())

	attrs := collectAttrs(p)

	cp := srpolicy.CandidatePath{
		Origin:        srpolicy.OriginBGP,
		Originator:    srpolicy.Originator{ASN: p.GetSourceAsn(), Node: originatorNode(p, attrs)},
		Discriminator: nlri.GetDistinguisher(),
		Preference:    srpolicy.DefaultPreference, // sub-TLV 不在時の既定 (RFC 9256 §2.7)
		Priority:      srpolicy.DefaultPriority,   // 同 §2.12 (低い値ほど高優先)
	}
	if attrs.tunnelEncap != nil {
		decodeTunnelEncap(attrs.tunnelEncap, &cp)
	}

	ev = srpolicy.Event{
		Key:      srpolicy.PolicyKey{Color: nlri.GetColor(), Endpoint: endpoint},
		Path:     cp,
		Withdraw: p.GetIsWithdraw(),
	}

	// 受信規則 (RFC 9830 §4.2.1/§4.2.2)。withdraw はそのまま通す。
	if !ev.Withdraw {
		if reason := usability(attrs, localID); reason != "" {
			ev.Withdraw = true // unusable → SRPM から削除 (treat-as-withdraw)
			note = reason
		}
	}
	return ev, true, note
}

// pathAttrs は decode に必要な path attribute をまとめて集めたもの。
type pathAttrs struct {
	tunnelEncap  *api.TunnelEncapAttribute
	communities  []uint32
	extComms     []*api.ExtendedCommunity
	originatorID netip.Addr // ORIGINATOR_ID attribute (RR 反射時)
}

func collectAttrs(p *api.Path) pathAttrs {
	var a pathAttrs
	for _, attr := range p.GetPattrs() {
		switch {
		case attr.GetTunnelEncap() != nil:
			a.tunnelEncap = attr.GetTunnelEncap()
		case attr.GetCommunities() != nil:
			a.communities = attr.GetCommunities().GetCommunities()
		case attr.GetExtendedCommunities() != nil:
			a.extComms = attr.GetExtendedCommunities().GetCommunities()
		case attr.GetOriginatorId() != nil:
			if id, err := netip.ParseAddr(attr.GetOriginatorId().GetId()); err == nil {
				a.originatorID = id
			}
		}
	}
	return a
}

// usability は RFC 9830 §4.2.1(検証)/§4.2.2(適格性)を適用し、
// 使用不可なら理由を、使用可なら "" を返す。
//   - RT も NO_ADVERTISE も無い → malformed (§4.2.1) → treat-as-withdraw
//   - RT あり → いずれかが受信ノードの BGP Identifier に一致しなければ not usable (§4.2.2)
//   - RT 無し + NO_ADVERTISE あり → usable (§4.2.2)
func usability(attrs pathAttrs, localID netip.Addr) string {
	var rts []netip.Addr
	for _, ec := range attrs.extComms {
		if v4 := ec.GetIpv4AddressSpecific(); v4 != nil && v4.GetSubType() == extSubTypeRouteTarget {
			if a, err := netip.ParseAddr(v4.GetAddress()); err == nil {
				rts = append(rts, a)
			}
		}
	}

	if len(rts) == 0 {
		if slices.Contains(attrs.communities, uint32(noAdvertise)) {
			return ""
		}
		return "malformed: no route target and no NO_ADVERTISE (RFC 9830 §4.2.1)"
	}
	if slices.Contains(rts, localID) {
		return ""
	}
	return fmt.Sprintf("not usable: no route target matches local BGP identifier %s (RFC 9830 §4.2.2)", localID)
}

// originatorNode は RFC 9830 §2.1 の優先順で originator の node address を決める:
// Route Origin community (IPv4-address-specific) > ORIGINATOR_ID > peer router-id。
func originatorNode(p *api.Path, attrs pathAttrs) netip.Addr {
	for _, ec := range attrs.extComms {
		if v4 := ec.GetIpv4AddressSpecific(); v4 != nil && v4.GetSubType() == extSubTypeRouteOrigin {
			if a, err := netip.ParseAddr(v4.GetAddress()); err == nil {
				return a
			}
		}
	}
	if attrs.originatorID.IsValid() {
		return attrs.originatorID
	}
	node, _ := netip.ParseAddr(p.GetSourceId()) // peer router-id (無ければ zero Addr)
	return node
}

// decodeTunnelEncap は SR Policy TLV (type 15) の sub-TLV 群を読む。
// RFC 9830 §2.2 により SR Policy TLV は 1 個のみ有効(2 個目以降は無視)。
// 単一インスタンス sub-TLV (preference/priority/BSID) は最初の 1 個のみ採用する
// (RFC 9830 §2.4: 重複は最初のインスタンスを使い、残りは無視)。
func decodeTunnelEncap(te *api.TunnelEncapAttribute, cp *srpolicy.CandidatePath) {
	for _, tlv := range te.GetTlvs() {
		if tlv.GetType() != tunnelTypeSRPolicy {
			continue
		}
		var havePref, havePrio, haveBSID, haveSRv6BSID bool
		for _, sub := range tlv.GetTlvs() {
			switch {
			case sub.GetSrBindingSid() != nil:
				// Binding SID sub-TLV (type 13)。SRv6 BSID sub-TLV (type 20) が
				// 既にあればそちらを優先 (RFC 9830 §2.4.2: type 13 は後方互換用)。
				if haveBSID || haveSRv6BSID {
					continue
				}
				if b := sub.GetSrBindingSid().GetSrBindingSid(); b != nil {
					cp.SpecifiedBSIDOnly = b.GetSFlag()
					cp.DropUponInvalid = b.GetIFlag()
					if a, ok := netip.AddrFromSlice(b.GetSid()); ok {
						cp.BSID = a
					}
					haveBSID = true
				}
			case sub.GetUnknown() != nil && sub.GetUnknown().GetType() == subTLVSRv6BSID:
				if haveSRv6BSID {
					continue
				}
				if sid, sFlag, iFlag, ok := parseSRv6BSID(sub.GetUnknown().GetValue()); ok {
					cp.BSID = sid
					cp.SpecifiedBSIDOnly = sFlag
					cp.DropUponInvalid = iFlag
					haveSRv6BSID = true
				}
			case sub.GetSrPreference() != nil:
				if !havePref {
					cp.Preference = sub.GetSrPreference().GetPreference()
					havePref = true
				}
			case sub.GetSrPriority() != nil:
				if !havePrio {
					cp.Priority = sub.GetSrPriority().GetPriority()
					havePrio = true
				}
			case sub.GetSrSegmentList() != nil:
				cp.SegmentLists = append(cp.SegmentLists, decodeSegmentList(sub.GetSrSegmentList()))
			}
		}
		return // SR Policy TLV は最初の 1 個のみ
	}
}

// parseSRv6BSID は SRv6 Binding SID sub-TLV (RFC 9830 §2.4.3) の value を読む。
// レイアウト: Flags(1) + RESERVED(1) + BSID(16) [+ Endpoint Behavior/Structure(8)]。
// Flags: S=0x80 (Specified-BSID-only), I=0x40 (Drop-upon-invalid), B=0x20 (behavior あり)。
func parseSRv6BSID(v []byte) (sid netip.Addr, sFlag, iFlag, ok bool) {
	if len(v) < 18 {
		return netip.Addr{}, false, false, false
	}
	a, ok := netip.AddrFromSlice(v[2:18])
	if !ok {
		return netip.Addr{}, false, false, false
	}
	return a, v[0]&0x80 != 0, v[0]&0x40 != 0, true
}

// decodeSegmentList は 1 本の segment list を読む。SegmentTypeB(SRv6 SID)のみ対応で、
// それ以外の segment type を含む list は Unsupported を立てて invalid にする
// (RFC 9256 §5.1: SR-MPLS/SRv6 混在 list は invalid。部分的に使ってはいけない)。
// weight 既定 1(RFC 9256 §2.2)、明示 0 は invalid のまま保持(§5.1)。
// V-Flag 付き segment は VerifyMask に記録する(RFC 9830 §2.4.4.2.3)。
func decodeSegmentList(in *api.TunnelEncapSubTLVSRSegmentList) srpolicy.SegmentList {
	out := srpolicy.SegmentList{Weight: 1}
	if w := in.GetWeight(); w != nil {
		out.Weight = w.GetWeight()
	}
	for _, seg := range in.GetSegments() {
		b := seg.GetB()
		if b == nil {
			out.Unsupported = true
			continue
		}
		if a, ok := netip.AddrFromSlice(b.GetSid()); ok {
			if b.GetFlags().GetVFlag() && len(out.SIDs) < 32 {
				out.VerifyMask |= 1 << uint(len(out.SIDs))
			}
			out.SIDs = append(out.SIDs, a)
		}
	}
	return out
}
