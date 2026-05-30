package usid

import (
	"net/netip"
	"testing"
)

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func block() Block {
	return Block{Prefix: netip.MustParsePrefix("fcbb:bb00::/32"), USIDBits: 16}
}

func TestValidateAndPerCarrier(t *testing.T) {
	b := block()
	if err := b.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := b.PerCarrier(); got != 6 { // (128-32)/16
		t.Fatalf("per carrier = %d, want 6", got)
	}
	bad := Block{Prefix: netip.MustParsePrefix("fcbb:bb00::/33"), USIDBits: 16}
	if err := bad.Validate(); err == nil {
		t.Fatal("non byte-aligned block must be invalid")
	}
}

func TestCompactSingleCarrier(t *testing.T) {
	got := block().Compact(addrs("fcbb:bb00:1::", "fcbb:bb00:2::", "fcbb:bb00:3::"))
	want := addrs("fcbb:bb00:1:2:3::")
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCompactSpillsToSecondCarrier(t *testing.T) {
	// 7 個 → 6 + 1 = 2 carrier
	got := block().Compact(addrs(
		"fcbb:bb00:1::", "fcbb:bb00:2::", "fcbb:bb00:3::",
		"fcbb:bb00:4::", "fcbb:bb00:5::", "fcbb:bb00:6::",
		"fcbb:bb00:7::",
	))
	want := addrs("fcbb:bb00:1:2:3:4:5:6", "fcbb:bb00:7::")
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCompactPassesThroughOutOfBlock(t *testing.T) {
	// block 外の SID は圧縮せず温存し、carrier を分断する
	got := block().Compact(addrs("fcbb:bb00:1::", "2001:db8:cafe::1", "fcbb:bb00:2::"))
	want := addrs("fcbb:bb00:1::", "2001:db8:cafe::1", "fcbb:bb00:2::")
	if len(got) != 3 {
		t.Fatalf("got %v, want 3 entries", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%s want %s", i, got[i], want[i])
		}
	}
}
