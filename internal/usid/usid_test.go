package usid

import (
	"net/netip"
	"testing"

	"github.com/ryskn/safi73-vpp/internal/srpolicy"
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

func TestCompactPassesThroughNonSingleUSID(t *testing.T) {
	// block 配下でも「単一 uSID + 残り全ゼロ」でないアドレスは圧縮対象外:
	// 既に複数 uSID が詰まった carrier のビットを黙って落としてはいけない。
	carrier := "fcbb:bb00:10:20:30::"
	got := block().Compact(addrs("fcbb:bb00:1::", carrier, "fcbb:bb00:2::"))
	want := addrs("fcbb:bb00:1::", carrier, "fcbb:bb00:2::")
	if len(got) != 3 {
		t.Fatalf("got %v, want 3 entries (carrier must not be re-compacted)", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%s want %s", i, got[i], want[i])
		}
	}
}

func TestCompactorCarriesVerifyMask(t *testing.T) {
	// 圧縮で SID と mask bit の対応が崩れるため、verification 要求は
	// 先頭 SID (carrier) への要求として引き継がれる
	c := Compactor{Block: block()}
	in := srpolicy.CandidatePath{SegmentLists: []srpolicy.SegmentList{
		{Weight: 1, SIDs: addrs("fcbb:bb00:1::", "fcbb:bb00:2::"), VerifyMask: 1 << 1},
		{Weight: 1, SIDs: addrs("fcbb:bb00:3::")}, // 要求なし
	}}
	out := c.Apply(in)
	if out.SegmentLists[0].VerifyMask != 1 {
		t.Fatalf("mask=%b, want 1 (verify carrier head)", out.SegmentLists[0].VerifyMask)
	}
	if out.SegmentLists[1].VerifyMask != 0 {
		t.Fatalf("mask=%b, want 0", out.SegmentLists[1].VerifyMask)
	}
}

func TestCompactPassesThroughBareBlockPrefix(t *testing.T) {
	// uSID 部が全ゼロ(= block そのもの)のアドレスは単一 uSID ではない
	got := block().Compact(addrs("fcbb:bb00::"))
	if len(got) != 1 || got[0] != netip.MustParseAddr("fcbb:bb00::") {
		t.Fatalf("got %v, want bare block prefix passthrough", got)
	}
}
