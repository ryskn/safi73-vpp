package bgp

import (
	"net"
	"net/netip"
	"testing"

	api "github.com/osrg/gobgp/v4/api"

	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

var testLocalID = netip.MustParseAddr("192.168.1.15")

func noAdvComm() *api.Attribute {
	return &api.Attribute{Attr: &api.Attribute_Communities{
		Communities: &api.CommunitiesAttribute{Communities: []uint32{noAdvertise}},
	}}
}

func rtComm(addrs ...string) *api.Attribute {
	var comms []*api.ExtendedCommunity
	for _, a := range addrs {
		comms = append(comms, &api.ExtendedCommunity{
			Extcom: &api.ExtendedCommunity_Ipv4AddressSpecific{
				Ipv4AddressSpecific: &api.IPv4AddressSpecificExtended{
					IsTransitive: true, SubType: extSubTypeRouteTarget, Address: a,
				},
			},
		})
	}
	return &api.Attribute{Attr: &api.Attribute_ExtendedCommunities{
		ExtendedCommunities: &api.ExtendedCommunitiesAttribute{Communities: comms},
	}}
}

func segListTLV(weight *uint32, sids ...string) *api.TunnelEncapTLV_TLV {
	var segs []*api.TunnelEncapSubTLVSRSegmentList_Segment
	for _, s := range sids {
		segs = append(segs, &api.TunnelEncapSubTLVSRSegmentList_Segment{
			Segment: &api.TunnelEncapSubTLVSRSegmentList_Segment_B{
				B: &api.SegmentTypeB{Sid: net.ParseIP(s).To16()},
			},
		})
	}
	sl := &api.TunnelEncapSubTLVSRSegmentList{Segments: segs}
	if weight != nil {
		sl.Weight = &api.SRWeight{Weight: *weight}
	}
	return &api.TunnelEncapTLV_TLV{Tlv: &api.TunnelEncapTLV_TLV_SrSegmentList{SrSegmentList: sl}}
}

func bsid13TLV(sid string) *api.TunnelEncapTLV_TLV {
	return &api.TunnelEncapTLV_TLV{Tlv: &api.TunnelEncapTLV_TLV_SrBindingSid{
		SrBindingSid: &api.TunnelEncapSubTLVSRBindingSID{
			Bsid: &api.TunnelEncapSubTLVSRBindingSID_SrBindingSid{
				SrBindingSid: &api.SRBindingSID{Sid: net.ParseIP(sid).To16()},
			},
		},
	}}
}

// bsid20TLV は SRv6 Binding SID sub-TLV (type 20) の wire value を Unknown として組む
// (gobgp が type 20 をパースしないことの再現)。
func bsid20TLV(sid string, flags byte) *api.TunnelEncapTLV_TLV {
	v := make([]byte, 18)
	v[0] = flags
	copy(v[2:], net.ParseIP(sid).To16())
	return &api.TunnelEncapTLV_TLV{Tlv: &api.TunnelEncapTLV_TLV_Unknown{
		Unknown: &api.TunnelEncapSubTLVUnknown{Type: subTLVSRv6BSID, Value: v},
	}}
}

func prefTLV(p uint32) *api.TunnelEncapTLV_TLV {
	return &api.TunnelEncapTLV_TLV{Tlv: &api.TunnelEncapTLV_TLV_SrPreference{
		SrPreference: &api.TunnelEncapSubTLVSRPreference{Preference: p},
	}}
}

// srPath は SAFI73 の 1 経路を組む。attrs には tunnel-encap 以外の path attribute。
func srPath(subTLVs []*api.TunnelEncapTLV_TLV, attrs ...*api.Attribute) *api.Path {
	pattrs := append([]*api.Attribute{
		{Attr: &api.Attribute_TunnelEncap{TunnelEncap: &api.TunnelEncapAttribute{
			Tlvs: []*api.TunnelEncapTLV{{Type: tunnelTypeSRPolicy, Tlvs: subTLVs}},
		}}},
	}, attrs...)
	return &api.Path{
		Family: &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_SR_POLICY},
		Nlri: &api.NLRI{Nlri: &api.NLRI_SrPolicy{SrPolicy: &api.SRPolicyNLRI{
			Length: 192, Distinguisher: 7, Color: 100,
			Endpoint: net.ParseIP("2001:db8::1").To16(),
		}}},
		Pattrs:    pattrs,
		SourceAsn: 65000,
		SourceId:  "10.0.0.3",
	}
}

func decodeOK(t *testing.T, p *api.Path) srpolicy.Event {
	t.Helper()
	ev, ok, note := decodePath(p, testLocalID)
	if !ok {
		t.Fatal("decodePath: not an SR Policy path")
	}
	if note != "" {
		t.Fatalf("unexpected usability note: %s", note)
	}
	return ev
}

func TestDecodeBasics(t *testing.T) {
	ev := decodeOK(t, srPath(
		[]*api.TunnelEncapTLV_TLV{prefTLV(200), bsid13TLV("2001:db8:b::1"), segListTLV(nil, "2001:db8:c::1", "2001:db8:c::2")},
		noAdvComm(),
	))
	if ev.Key.Color != 100 || ev.Key.Endpoint != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("key=%+v", ev.Key)
	}
	cp := ev.Path
	if cp.Discriminator != 7 || cp.Preference != 200 || cp.BSID != netip.MustParseAddr("2001:db8:b::1") {
		t.Fatalf("cp=%+v", cp)
	}
	if len(cp.SegmentLists) != 1 || cp.SegmentLists[0].Weight != 1 { // weight 既定 1 (RFC 9256 §2.2)
		t.Fatalf("segment lists=%+v", cp.SegmentLists)
	}
	if !cp.Valid() {
		t.Fatal("cp should be valid")
	}
}

// Preference sub-TLV 不在 → 既定 100 (RFC 9256 §2.7)。0 になってはいけない。
func TestPreferenceDefaults100(t *testing.T) {
	ev := decodeOK(t, srPath(
		[]*api.TunnelEncapTLV_TLV{bsid13TLV("2001:db8:b::1"), segListTLV(nil, "2001:db8:c::1")},
		noAdvComm(),
	))
	if ev.Path.Preference != srpolicy.DefaultPreference {
		t.Fatalf("preference=%d, want %d", ev.Path.Preference, srpolicy.DefaultPreference)
	}
}

// SRv6 Binding SID sub-TLV (type 20) は gobgp から Unknown で届く。自前パースで拾う。
func TestSRv6BindingSIDSubTLV(t *testing.T) {
	ev := decodeOK(t, srPath(
		[]*api.TunnelEncapTLV_TLV{bsid20TLV("2001:db8:b::20", 0xC0), segListTLV(nil, "2001:db8:c::1")},
		noAdvComm(),
	))
	cp := ev.Path
	if cp.BSID != netip.MustParseAddr("2001:db8:b::20") {
		t.Fatalf("bsid=%s, want 2001:db8:b::20 (from type-20 sub-TLV)", cp.BSID)
	}
	if !cp.SpecifiedBSIDOnly || !cp.DropUponInvalid { // flags 0xC0 = S|I
		t.Fatalf("flags: S=%v I=%v, want both true", cp.SpecifiedBSIDOnly, cp.DropUponInvalid)
	}
}

// type 13 と type 20 が両方あれば type 20 を優先 (RFC 9830 §2.4.2: 13 は後方互換用)。
func TestSRv6BSIDPreferredOverLegacy(t *testing.T) {
	ev := decodeOK(t, srPath(
		[]*api.TunnelEncapTLV_TLV{
			bsid13TLV("2001:db8:b::13"),
			bsid20TLV("2001:db8:b::20", 0),
			segListTLV(nil, "2001:db8:c::1"),
		},
		noAdvComm(),
	))
	if ev.Path.BSID != netip.MustParseAddr("2001:db8:b::20") {
		t.Fatalf("bsid=%s, want type-20 to win", ev.Path.BSID)
	}
}

// SR-MPLS(Type A)を含む list は Unsupported → invalid (RFC 9256 §5.1 混在禁止)。
func TestMixedSegmentTypesInvalid(t *testing.T) {
	mixed := segListTLV(nil, "2001:db8:c::1")
	mixed.GetSrSegmentList().Segments = append(mixed.GetSrSegmentList().Segments,
		&api.TunnelEncapSubTLVSRSegmentList_Segment{
			Segment: &api.TunnelEncapSubTLVSRSegmentList_Segment_A{
				A: &api.SegmentTypeA{Label: 16001},
			},
		})
	ev := decodeOK(t, srPath(
		[]*api.TunnelEncapTLV_TLV{bsid13TLV("2001:db8:b::1"), mixed},
		noAdvComm(),
	))
	if len(ev.Path.SegmentLists) != 1 {
		t.Fatalf("segment lists=%d, want 1", len(ev.Path.SegmentLists))
	}
	if !ev.Path.SegmentLists[0].Unsupported {
		t.Fatal("mixed-type list must be marked unsupported")
	}
	if ev.Path.Valid() {
		t.Fatal("cp with only a mixed-type list must be invalid")
	}
}

// SR Policy 以外の tunnel type の TLV は読まない (RFC 9830 §2.2)。
func TestNonSRPolicyTunnelTypeIgnored(t *testing.T) {
	p := srPath([]*api.TunnelEncapTLV_TLV{bsid13TLV("2001:db8:b::1"), segListTLV(nil, "2001:db8:c::1")}, noAdvComm())
	// 先頭に別 tunnel type (VXLAN=8) の TLV を足し、そこに preference を置く
	p.Pattrs[0] = &api.Attribute{Attr: &api.Attribute_TunnelEncap{TunnelEncap: &api.TunnelEncapAttribute{
		Tlvs: []*api.TunnelEncapTLV{
			{Type: 8, Tlvs: []*api.TunnelEncapTLV_TLV{prefTLV(999)}},
			{Type: tunnelTypeSRPolicy, Tlvs: []*api.TunnelEncapTLV_TLV{bsid13TLV("2001:db8:b::1"), segListTLV(nil, "2001:db8:c::1")}},
		},
	}}}
	ev := decodeOK(t, p)
	if ev.Path.Preference != srpolicy.DefaultPreference {
		t.Fatalf("preference=%d leaked from non-SR-Policy TLV", ev.Path.Preference)
	}
	if ev.Path.BSID != netip.MustParseAddr("2001:db8:b::1") {
		t.Fatalf("bsid=%s", ev.Path.BSID)
	}
}

// 単一インスタンス sub-TLV の重複は最初のインスタンスを使う (RFC 9830 §2.4)。
func TestDuplicateSubTLVFirstWins(t *testing.T) {
	ev := decodeOK(t, srPath(
		[]*api.TunnelEncapTLV_TLV{prefTLV(500), prefTLV(300), bsid13TLV("2001:db8:b::1"), segListTLV(nil, "2001:db8:c::1")},
		noAdvComm(),
	))
	if ev.Path.Preference != 500 {
		t.Fatalf("preference=%d, want 500 (first instance)", ev.Path.Preference)
	}
}

func usableTLVs() []*api.TunnelEncapTLV_TLV {
	return []*api.TunnelEncapTLV_TLV{bsid13TLV("2001:db8:b::1"), segListTLV(nil, "2001:db8:c::1")}
}

// RFC 9830 §4.2.1/§4.2.2 の受信規則。
func TestUsability(t *testing.T) {
	// RT も NO_ADVERTISE も無い → malformed → treat-as-withdraw
	ev, ok, note := decodePath(srPath(usableTLVs()), testLocalID)
	if !ok || !ev.Withdraw || note == "" {
		t.Fatalf("no RT/no NO_ADVERTISE: withdraw=%v note=%q", ev.Withdraw, note)
	}
	// NO_ADVERTISE のみ → usable
	if ev := decodeOK(t, srPath(usableTLVs(), noAdvComm())); ev.Withdraw {
		t.Fatal("NO_ADVERTISE only must be usable")
	}
	// RT が自ノードの BGP Identifier に一致 → usable
	if ev := decodeOK(t, srPath(usableTLVs(), rtComm("10.9.9.9", testLocalID.String()))); ev.Withdraw {
		t.Fatal("matching RT must be usable")
	}
	// RT 不一致 → not usable → treat-as-withdraw
	ev, _, note = decodePath(srPath(usableTLVs(), rtComm("10.9.9.9")), testLocalID)
	if !ev.Withdraw || note == "" {
		t.Fatalf("mismatched RT: withdraw=%v note=%q", ev.Withdraw, note)
	}
	// withdraw はそのまま通す(usability 判定なし)
	wd := srPath(usableTLVs())
	wd.IsWithdraw = true
	ev, _, note = decodePath(wd, testLocalID)
	if !ev.Withdraw || note != "" {
		t.Fatalf("withdraw passthrough: withdraw=%v note=%q", ev.Withdraw, note)
	}
}

// Originator node の導出優先順 (RFC 9830 §2.1):
// Route Origin community > ORIGINATOR_ID > peer router-id。
func TestOriginatorNodePrecedence(t *testing.T) {
	routeOrigin := &api.Attribute{Attr: &api.Attribute_ExtendedCommunities{
		ExtendedCommunities: &api.ExtendedCommunitiesAttribute{Communities: []*api.ExtendedCommunity{{
			Extcom: &api.ExtendedCommunity_Ipv4AddressSpecific{
				Ipv4AddressSpecific: &api.IPv4AddressSpecificExtended{
					IsTransitive: true, SubType: extSubTypeRouteOrigin, Address: "10.0.0.1",
				},
			},
		}}},
	}}
	originatorID := &api.Attribute{Attr: &api.Attribute_OriginatorId{
		OriginatorId: &api.OriginatorIdAttribute{Id: "10.0.0.2"},
	}}

	ev := decodeOK(t, srPath(usableTLVs(), noAdvComm(), routeOrigin, originatorID))
	if got := ev.Path.Originator.Node; got != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("node=%s, want route-origin community to win", got)
	}
	ev = decodeOK(t, srPath(usableTLVs(), noAdvComm(), originatorID))
	if got := ev.Path.Originator.Node; got != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("node=%s, want ORIGINATOR_ID", got)
	}
	ev = decodeOK(t, srPath(usableTLVs(), noAdvComm()))
	if got := ev.Path.Originator.Node; got != netip.MustParseAddr("10.0.0.3") {
		t.Fatalf("node=%s, want peer router-id (source-id)", got)
	}
	if ev.Path.Originator.ASN != 65000 {
		t.Fatalf("asn=%d", ev.Path.Originator.ASN)
	}
}
