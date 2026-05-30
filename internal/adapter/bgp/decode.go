package bgp

import (
	"net/netip"

	api "github.com/osrg/gobgp/v4/api"

	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

// decodePath は gobgp の api.Path を srpolicy.Event に変換する。
// SR Policy (SAFI 73) でなければ ok=false。
func decodePath(p *api.Path) (srpolicy.Event, bool) {
	if p.GetFamily().GetSafi() != api.Family_SAFI_SR_POLICY {
		return srpolicy.Event{}, false
	}
	nlri := p.GetNlri().GetSrPolicy()
	if nlri == nil {
		return srpolicy.Event{}, false
	}
	endpoint, _ := netip.AddrFromSlice(nlri.GetEndpoint())
	pol := srpolicy.Policy{
		Distinguisher: nlri.GetDistinguisher(),
		Color:         nlri.GetColor(),
		Endpoint:      endpoint,
	}
	for _, attr := range p.GetPattrs() {
		if te := attr.GetTunnelEncap(); te != nil {
			decodeTunnelEncap(te, &pol)
		}
	}
	return srpolicy.Event{Policy: pol, Withdraw: p.GetIsWithdraw()}, true
}

// decodeTunnelEncap は Tunnel Encapsulation attribute の SR Policy sub-TLV 群を読む。
func decodeTunnelEncap(te *api.TunnelEncapAttribute, pol *srpolicy.Policy) {
	for _, tlv := range te.GetTlvs() {
		for _, sub := range tlv.GetTlvs() {
			switch {
			case sub.GetSrBindingSid() != nil:
				if b := sub.GetSrBindingSid().GetSrBindingSid(); b != nil {
					if a, ok := netip.AddrFromSlice(b.GetSid()); ok {
						pol.BSID = a
					}
				}
			case sub.GetSrPreference() != nil:
				pol.Preference = sub.GetSrPreference().GetPreference()
			case sub.GetSrSegmentList() != nil:
				if sl, ok := decodeSegmentList(sub.GetSrSegmentList()); ok {
					pol.SegmentLists = append(pol.SegmentLists, sl)
				}
			}
		}
	}
}

// decodeSegmentList は 1 本の segment list を読む。SegmentTypeB(SRv6 SID)のみ拾い、
// SegmentTypeA(SR-MPLS label)は対象外。
func decodeSegmentList(in *api.TunnelEncapSubTLVSRSegmentList) (srpolicy.SegmentList, bool) {
	out := srpolicy.SegmentList{}
	if w := in.GetWeight(); w != nil {
		out.Weight = w.GetWeight()
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
