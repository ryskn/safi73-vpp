package control

import (
	"context"
	"net/netip"
	"testing"

	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

// fakeProgrammer は Programmer の検証用 fake(VPP 不要)。
type fakeProgrammer struct {
	added   []srpolicy.Policy
	removed []srpolicy.Policy
}

func (f *fakeProgrammer) Add(p srpolicy.Policy) error {
	f.added = append(f.added, p)
	return nil
}

func (f *fakeProgrammer) Remove(p srpolicy.Policy) error {
	f.removed = append(f.removed, p)
	return nil
}

// sliceSource は固定イベント列を流す Source の fake(gobgp 不要)。
type sliceSource struct{ events []srpolicy.Event }

func (s sliceSource) Subscribe(_ context.Context, h func(srpolicy.Event)) error {
	for _, e := range s.events {
		h(e)
	}
	return nil
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func policy(color uint32, bsid string) srpolicy.Policy {
	return srpolicy.Policy{
		Color:    color,
		Endpoint: mustAddr("2001:db8::1"),
		BSID:     mustAddr(bsid),
		SegmentLists: []srpolicy.SegmentList{
			{Weight: 1, SIDs: []netip.Addr{mustAddr("2001:db8:c::1")}},
		},
	}
}

func run(t *testing.T, evs []srpolicy.Event) *fakeProgrammer {
	t.Helper()
	fp := &fakeProgrammer{}
	r := NewReconciler(sliceSource{evs}, fp, NewMemStore(), nil)
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	return fp
}

func TestAddThenWithdraw(t *testing.T) {
	p := policy(100, "2001:db8:b::1")
	fp := run(t, []srpolicy.Event{{Policy: p}, {Policy: p, Withdraw: true}})
	if len(fp.added) != 1 || len(fp.removed) != 1 {
		t.Fatalf("added=%d removed=%d, want 1/1", len(fp.added), len(fp.removed))
	}
}

func TestUpdateRemovesOldFirst(t *testing.T) {
	p1 := policy(100, "2001:db8:b::1")
	p2 := policy(100, "2001:db8:b::2") // 同一 key・別 BSID
	fp := run(t, []srpolicy.Event{{Policy: p1}, {Policy: p2}})
	if len(fp.added) != 2 || len(fp.removed) != 1 {
		t.Fatalf("added=%d removed=%d, want 2/1", len(fp.added), len(fp.removed))
	}
	if fp.removed[0].BSID != p1.BSID {
		t.Fatalf("removed old bsid=%s, want %s", fp.removed[0].BSID, p1.BSID)
	}
}

func TestSkipInvalidPolicy(t *testing.T) {
	bad := policy(100, "2001:db8:b::1")
	bad.SegmentLists = nil // SRv6 不成立
	fp := run(t, []srpolicy.Event{{Policy: bad}})
	if len(fp.added) != 0 {
		t.Fatalf("added=%d, want 0", len(fp.added))
	}
}

func TestWithdrawUnknownIsNoop(t *testing.T) {
	fp := run(t, []srpolicy.Event{{Policy: policy(100, "2001:db8:b::1"), Withdraw: true}})
	if len(fp.removed) != 0 {
		t.Fatalf("removed=%d, want 0", len(fp.removed))
	}
}

// markTransform は変換が確かに適用されるか確認するための fake。
type markTransform struct{ called *int }

func (m markTransform) Apply(p srpolicy.Policy) srpolicy.Policy {
	*m.called++
	p.BSID = mustAddr("2001:db8:b::ff") // 変換結果が投入されることを示す
	return p
}

func TestTransformIsApplied(t *testing.T) {
	called := 0
	fp := &fakeProgrammer{}
	r := NewReconciler(sliceSource{[]srpolicy.Event{{Policy: policy(100, "2001:db8:b::1")}}},
		fp, NewMemStore(), nil, WithTransform(markTransform{&called}))
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if called != 1 {
		t.Fatalf("transform called %d times, want 1", called)
	}
	if len(fp.added) != 1 || fp.added[0].BSID != mustAddr("2001:db8:b::ff") {
		t.Fatalf("programmed policy did not reflect transform: %+v", fp.added)
	}
}
