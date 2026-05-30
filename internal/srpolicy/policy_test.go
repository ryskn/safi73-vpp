package srpolicy

import (
	"net/netip"
	"testing"
)

func TestValidateSRv6(t *testing.T) {
	good := Policy{
		BSID:         netip.MustParseAddr("2001:db8::1"),
		SegmentLists: []SegmentList{{SIDs: []netip.Addr{netip.MustParseAddr("2001:db8::2")}}},
	}
	if err := good.ValidateSRv6(); err != nil {
		t.Fatalf("want valid, got %v", err)
	}

	cases := map[string]Policy{
		"v4 bsid":     {BSID: netip.MustParseAddr("10.0.0.1"), SegmentLists: good.SegmentLists},
		"no segments": {BSID: good.BSID},
		"empty sl":    {BSID: good.BSID, SegmentLists: []SegmentList{{}}},
	}
	for name, p := range cases {
		if err := p.ValidateSRv6(); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

func TestKeyStableAndDistinct(t *testing.T) {
	a := Policy{Distinguisher: 1, Color: 2, Endpoint: netip.MustParseAddr("2001:db8::1")}
	b := Policy{Distinguisher: 1, Color: 3, Endpoint: netip.MustParseAddr("2001:db8::1")}
	if a.Key() != a.Key() {
		t.Fatal("key not stable")
	}
	if a.Key() == b.Key() {
		t.Fatal("different color must yield different key")
	}
}
