package bgp

import (
	"net/netip"

	api "github.com/osrg/gobgp/v4/api"

	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

// decodePath は gobgp の api.Path を srpolicy.Event(= 1 candidate path の更新)に変換する。
// SR Policy (SAFI 73) でなければ ok=false。
//
// SR Policy(<color,endpoint>)とその candidate path 識別子は次のように対応付ける:
//   - color / endpoint     <- NLRI
//   - protocol-origin      <- BGP(20) 固定
//   - originator(ASN,node) <- 経路の source ASN / source-id
//   - discriminator        <- NLRI の distinguisher
func decodePath(p *api.Path) (srpolicy.Event, bool) {
	if p.GetFamily().GetSafi() != api.Family_SAFI_SR_POLICY {
		return srpolicy.Event{}, false
	}
	nlri := p.GetNlri().GetSrPolicy()
	if nlri == nil {
		return srpolicy.Event{}, false
	}
	endpoint, _ := netip.AddrFromSlice(nlri.GetEndpoint())
	node, _ := netip.ParseAddr(p.GetSourceId()) // router-id (無ければ zero Addr)

	cp := srpolicy.CandidatePath{
		Origin:        srpolicy.OriginBGP,
		Originator:    srpolicy.Originator{ASN: p.GetSourceAsn(), Node: node},
		Discriminator: nlri.GetDistinguisher(),
	}
	for _, attr := range p.GetPattrs() {
		if te := attr.GetTunnelEncap(); te != nil {
			decodeTunnelEncap(te, &cp)
		}
	}

	ev := srpolicy.Event{
		Key:      srpolicy.PolicyKey{Color: nlri.GetColor(), Endpoint: endpoint},
		Path:     cp,
		Withdraw: p.GetIsWithdraw(),
	}
	return ev, true
}

// decodeTunnelEncap は Tunnel Encapsulation attribute の SR Policy sub-TLV 群を読む。
func decodeTunnelEncap(te *api.TunnelEncapAttribute, cp *srpolicy.CandidatePath) {
	for _, tlv := range te.GetTlvs() {
		for _, sub := range tlv.GetTlvs() {
			switch {
			case sub.GetSrBindingSid() != nil:
				if b := sub.GetSrBindingSid().GetSrBindingSid(); b != nil {
					if a, ok := netip.AddrFromSlice(b.GetSid()); ok {
						cp.BSID = a
					}
				}
			case sub.GetSrPreference() != nil:
				cp.Preference = sub.GetSrPreference().GetPreference()
			case sub.GetSrPriority() != nil:
				cp.Priority = sub.GetSrPriority().GetPriority()
			case sub.GetSrSegmentList() != nil:
				if sl, ok := decodeSegmentList(sub.GetSrSegmentList()); ok {
					cp.SegmentLists = append(cp.SegmentLists, sl)
				}
			}
		}
	}
}

// decodeSegmentList は 1 本の segment list を読む。SegmentTypeB(SRv6 SID)のみ拾い、
// SegmentTypeA(SR-MPLS label)は対象外。weight 既定 1(RFC 9256)。
func decodeSegmentList(in *api.TunnelEncapSubTLVSRSegmentList) (srpolicy.SegmentList, bool) {
	out := srpolicy.SegmentList{Weight: 1}
	if w := in.GetWeight(); w != nil {
		out.Weight = w.GetWeight() // 明示 0 は invalid のまま保持(RFC 9256 §5.1)
	}
	for _, seg := range in.GetSegments() {
		if b := seg.GetB(); b != nil {
			if a, ok := netip.AddrFromSlice(b.GetSid()); ok {
				out.SIDs = append(out.SIDs, a)
			}
		}
	}
	return out, len(out.SIDs) > 0
}
