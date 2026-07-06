package srpolicy

import (
	"fmt"
	"net/netip"
	"testing"
)

func sl(weight uint32, sids ...string) SegmentList {
	a := make([]netip.Addr, len(sids))
	for i, s := range sids {
		a[i] = netip.MustParseAddr(s)
	}
	return SegmentList{Weight: weight, SIDs: a}
}

func cp(pref uint32, origin ProtocolOrigin, asn uint32, node string, disc uint32) CandidatePath {
	return CandidatePath{
		Origin:        origin,
		Originator:    Originator{ASN: asn, Node: netip.MustParseAddr(node)},
		Discriminator: disc,
		Preference:    pref,
		BSID:          netip.MustParseAddr("2001:db8:b::1"),
		SegmentLists:  []SegmentList{sl(1, "2001:db8:c::1")},
	}
}

func TestSegmentListValidity(t *testing.T) {
	if !sl(1, "2001:db8::1").Valid() {
		t.Error("normal SID-list should be valid")
	}
	if sl(0, "2001:db8::1").Valid() {
		t.Error("weight 0 must be invalid")
	}
	if sl(1).Valid() {
		t.Error("empty must be invalid")
	}
	if sl(1, "10.0.0.1").Valid() {
		t.Error("non-IPv6 SID must be invalid")
	}

	// 混在 segment type (RFC 9256 §5.1): 部分的に使わず list ごと invalid
	mixed := sl(1, "2001:db8::1")
	mixed.Unsupported = true
	if mixed.Valid() {
		t.Error("list containing unsupported segment types must be invalid")
	}

	// headend 上限超過は切り詰めず invalid
	over := SegmentList{Weight: 1}
	for i := 0; i <= MaxSIDsPerList; i++ {
		over.SIDs = append(over.SIDs, netip.MustParseAddr(fmt.Sprintf("2001:db8:c::%x", i+1)))
	}
	if over.Valid() {
		t.Errorf("list with %d SIDs (> %d) must be invalid", len(over.SIDs), MaxSIDsPerList)
	}
	atLimit := SegmentList{Weight: 1, SIDs: over.SIDs[:MaxSIDsPerList]}
	if !atLimit.Valid() {
		t.Errorf("list with exactly %d SIDs should be valid", MaxSIDsPerList)
	}
}

func TestCandidatePathBSIDValidity(t *testing.T) {
	base := cp(100, OriginBGP, 1, "2001:db8::1", 1)

	// BSID 未指定は valid (動的割当対象, §6.2.1)。割当可否は headend 側の判定
	noBSID := base
	noBSID.BSID = netip.Addr{}
	if !noBSID.Valid() {
		t.Error("cp without BSID should be valid (dynamic allocation candidate)")
	}

	// S-Flag 付きで BSID 未指定は invalid (§6.2.3)
	sOnly := noBSID
	sOnly.SpecifiedBSIDOnly = true
	if sOnly.Valid() {
		t.Error("S-Flag without BSID must be invalid")
	}

	// BSID が指定されているのに IPv4 は invalid
	v4 := base
	v4.BSID = netip.MustParseAddr("10.0.0.1")
	if v4.Valid() {
		t.Error("IPv4 BSID must be invalid")
	}
}

func TestSelectHighestPreference(t *testing.T) {
	a := cp(100, OriginBGP, 1, "2001:db8::1", 1)
	b := cp(200, OriginBGP, 1, "2001:db8::1", 2)
	got, ok := SelectActive([]CandidatePath{a, b}, CPKey{}, false)
	if !ok || got.Preference != 200 {
		t.Fatalf("want pref 200, got %+v ok=%v", got, ok)
	}
}

func TestTieProtocolOriginHigher(t *testing.T) {
	a := cp(100, OriginBGP, 1, "2001:db8::1", 1)    // 20
	b := cp(100, OriginConfig, 1, "2001:db8::1", 1) // 30
	got, _ := SelectActive([]CandidatePath{a, b}, CPKey{}, false)
	if got.Origin != OriginConfig {
		t.Fatalf("want higher protocol-origin (Config), got %v", got.Origin)
	}
}

func TestTieOriginatorLower(t *testing.T) {
	a := cp(100, OriginBGP, 10, "2001:db8::1", 1)
	b := cp(100, OriginBGP, 5, "2001:db8::1", 1) // 低い ASN
	got, _ := SelectActive([]CandidatePath{a, b}, CPKey{}, false)
	if got.Originator.ASN != 5 {
		t.Fatalf("want lower originator ASN 5, got %d", got.Originator.ASN)
	}
}

func TestTieDiscriminatorHigher(t *testing.T) {
	a := cp(100, OriginBGP, 1, "2001:db8::1", 1)
	b := cp(100, OriginBGP, 1, "2001:db8::1", 9) // 高い discriminator
	got, _ := SelectActive([]CandidatePath{a, b}, CPKey{}, false)
	if got.Discriminator != 9 {
		t.Fatalf("want higher discriminator 9, got %d", got.Discriminator)
	}
}

func TestPreferExistingOnTie(t *testing.T) {
	a := cp(100, OriginBGP, 1, "2001:db8::1", 1)
	b := cp(100, OriginBGP, 1, "2001:db8::1", 9) // 本来 b が勝つ(disc高)
	// 既存 active が a の場合は a を維持(フラップ抑制)
	got, _ := SelectActive([]CandidatePath{a, b}, a.Key(), true)
	if got.Discriminator != 1 {
		t.Fatalf("want existing (disc 1) retained, got %d", got.Discriminator)
	}
}

func TestNoValidCandidate(t *testing.T) {
	bad := cp(100, OriginBGP, 1, "2001:db8::1", 1)
	bad.SegmentLists = nil
	if _, ok := SelectActive([]CandidatePath{bad}, CPKey{}, false); ok {
		t.Fatal("no valid CP must yield ok=false")
	}
}
