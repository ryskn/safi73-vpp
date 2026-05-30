package control

import (
	"context"
	"net/netip"
	"testing"

	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

// fakeProgrammer は Programmer の検証用 fake(VPP 不要)。
type fakeProgrammer struct {
	added   []srpolicy.CandidatePath
	removed []srpolicy.CandidatePath
}

func (f *fakeProgrammer) Add(cp srpolicy.CandidatePath) error {
	f.added = append(f.added, cp)
	return nil
}
func (f *fakeProgrammer) Remove(cp srpolicy.CandidatePath) error {
	f.removed = append(f.removed, cp)
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

var polKey = srpolicy.PolicyKey{Color: 100, Endpoint: mustAddr("2001:db8::1")}

// cpEvent は同一 SR Policy <color=100,endpoint=2001:db8::1> の candidate path イベント。
func cpEvent(disc, pref uint32, bsid string, withdraw bool) srpolicy.Event {
	return srpolicy.Event{
		Key:      polKey,
		Withdraw: withdraw,
		Path: srpolicy.CandidatePath{
			Origin:        srpolicy.OriginBGP,
			Originator:    srpolicy.Originator{ASN: 65000, Node: mustAddr("2001:db8::ffff")},
			Discriminator: disc,
			Preference:    pref,
			BSID:          mustAddr(bsid),
			SegmentLists:  []srpolicy.SegmentList{{Weight: 1, SIDs: []netip.Addr{mustAddr("2001:db8:c::1")}}},
		},
	}
}

func run(t *testing.T, evs []srpolicy.Event, opts ...Option) *fakeProgrammer {
	t.Helper()
	fp := &fakeProgrammer{}
	r := NewReconciler(sliceSource{evs}, fp, nil, opts...)
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	return fp
}

// 同一 SR Policy に preference 違いの 2 CP → 高い方だけ instantiate。
func TestSelectsHighestPreference(t *testing.T) {
	fp := run(t, []srpolicy.Event{
		cpEvent(1, 100, "2001:db8:b::1", false),
		cpEvent(2, 200, "2001:db8:b::2", false),
	})
	if len(fp.added) != 2 {
		t.Fatalf("added=%d, want 2 (low then switch to high)", len(fp.added))
	}
	last := fp.added[len(fp.added)-1]
	if last.BSID != mustAddr("2001:db8:b::2") {
		t.Fatalf("active bsid=%s, want b::2 (pref 200)", last.BSID)
	}
}

// active CP を withdraw → 残る低 preference CP へ failover(旧 remove + 新 add)。
func TestFailoverOnWithdraw(t *testing.T) {
	fp := run(t, []srpolicy.Event{
		cpEvent(1, 100, "2001:db8:b::1", false), // 低
		cpEvent(2, 200, "2001:db8:b::2", false), // 高(active)
		cpEvent(2, 200, "2001:db8:b::2", true),  // active を withdraw
	})
	// 最後の add は b::1 (failover 先)、b::2 は remove されている
	last := fp.added[len(fp.added)-1]
	if last.BSID != mustAddr("2001:db8:b::1") {
		t.Fatalf("failover bsid=%s, want b::1", last.BSID)
	}
	removedB2 := false
	for _, r := range fp.removed {
		if r.BSID == mustAddr("2001:db8:b::2") {
			removedB2 = true
		}
	}
	if !removedB2 {
		t.Fatal("withdrawn active (b::2) must be removed from dataplane")
	}
}

// invalid CP (segment list 無し) は instantiate されない。
func TestInvalidCandidateNotInstalled(t *testing.T) {
	bad := cpEvent(1, 100, "2001:db8:b::1", false)
	bad.Path.SegmentLists = nil
	fp := run(t, []srpolicy.Event{bad})
	if len(fp.added) != 0 {
		t.Fatalf("added=%d, want 0 (invalid CP)", len(fp.added))
	}
}

// 全 CP が消えたら SR Policy はダウン(remove される)。
func TestPolicyDownWhenAllWithdrawn(t *testing.T) {
	fp := run(t, []srpolicy.Event{
		cpEvent(1, 100, "2001:db8:b::1", false),
		cpEvent(1, 100, "2001:db8:b::1", true),
	})
	if len(fp.removed) != 1 {
		t.Fatalf("removed=%d, want 1", len(fp.removed))
	}
}

// markTransform は変換が active CP に適用されることの確認用。
type markTransform struct{ called *int }

func (m markTransform) Apply(cp srpolicy.CandidatePath) srpolicy.CandidatePath {
	*m.called++
	cp.BSID = mustAddr("2001:db8:b::ff")
	return cp
}

func TestTransformAppliedToActive(t *testing.T) {
	called := 0
	fp := run(t, []srpolicy.Event{cpEvent(1, 100, "2001:db8:b::1", false)}, WithTransform(markTransform{&called}))
	if called == 0 || len(fp.added) != 1 || fp.added[0].BSID != mustAddr("2001:db8:b::ff") {
		t.Fatalf("transform not applied to active CP: called=%d added=%+v", called, fp.added)
	}
}
