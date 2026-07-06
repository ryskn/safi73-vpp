package control

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

// fakeProgrammer は Programmer(+Resyncer)の検証用 fake(VPP 不要)。
type fakeProgrammer struct {
	added    []srpolicy.CandidatePath
	replaced [][2]srpolicy.CandidatePath // {prev, next}
	removed  []srpolicy.CandidatePath

	failAdd    bool
	failRemove bool

	preinstalled []netip.Addr // InstalledBSIDs が返す既存 BSID
	gcRemoved    []netip.Addr // RemoveBSID で消されたもの
}

func (f *fakeProgrammer) Add(_ srpolicy.PolicyKey, cp srpolicy.CandidatePath) error {
	if f.failAdd {
		return fmt.Errorf("add failed")
	}
	f.added = append(f.added, cp)
	return nil
}

func (f *fakeProgrammer) Replace(_ srpolicy.PolicyKey, prev, next srpolicy.CandidatePath) error {
	if f.failAdd {
		return fmt.Errorf("replace failed")
	}
	f.replaced = append(f.replaced, [2]srpolicy.CandidatePath{prev, next})
	return nil
}

func (f *fakeProgrammer) Remove(_ srpolicy.PolicyKey, cp srpolicy.CandidatePath) error {
	if f.failRemove {
		return fmt.Errorf("remove failed")
	}
	f.removed = append(f.removed, cp)
	return nil
}

func (f *fakeProgrammer) InstalledBSIDs() ([]netip.Addr, error) { return f.preinstalled, nil }
func (f *fakeProgrammer) RemoveBSID(b netip.Addr) error {
	f.gcRemoved = append(f.gcRemoved, b)
	return nil
}

// lastActive は「いま dataplane で active な CP」相当(最後の add/replace 結果)。
func (f *fakeProgrammer) lastActive(t *testing.T) srpolicy.CandidatePath {
	t.Helper()
	lastAdd := len(f.added) - 1
	if len(f.replaced) > 0 {
		return f.replaced[len(f.replaced)-1][1]
	}
	if lastAdd < 0 {
		t.Fatal("nothing installed")
	}
	return f.added[lastAdd]
}

// sliceSource は固定イベント列を流して synced を呼ぶ Source の fake(gobgp 不要)。
type sliceSource struct{ events []srpolicy.Event }

func (s sliceSource) Subscribe(_ context.Context, h func(srpolicy.Event), synced func()) error {
	for _, e := range s.events {
		h(e)
	}
	if synced != nil {
		synced()
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

// 同一 SR Policy に preference 違いの 2 CP → 高い方だけが active。
func TestSelectsHighestPreference(t *testing.T) {
	fp := run(t, []srpolicy.Event{
		cpEvent(1, 100, "2001:db8:b::1", false),
		cpEvent(2, 200, "2001:db8:b::2", false),
	})
	if got := fp.lastActive(t).BSID; got != mustAddr("2001:db8:b::2") {
		t.Fatalf("active bsid=%s, want b::2 (pref 200)", got)
	}
	// 切替は Replace(make-before-break)経由で行われる
	if len(fp.replaced) != 1 {
		t.Fatalf("replaced=%d, want 1", len(fp.replaced))
	}
}

// active CP を withdraw → 残る低 preference CP へ failover。
func TestFailoverOnWithdraw(t *testing.T) {
	fp := run(t, []srpolicy.Event{
		cpEvent(1, 100, "2001:db8:b::1", false), // 低
		cpEvent(2, 200, "2001:db8:b::2", false), // 高(active)
		cpEvent(2, 200, "2001:db8:b::2", true),  // active を withdraw
	})
	if got := fp.lastActive(t).BSID; got != mustAddr("2001:db8:b::1") {
		t.Fatalf("failover bsid=%s, want b::1", got)
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

// gobgp の TYPE_BEST は同一 NLRI の best 切替で旧 best の withdraw を流さない。
// 同じ distinguisher で originator が変わった announce は「置換」であり、
// 旧 originator の CP が幽霊として残って選択に参加してはならない。
func TestSameDiscriminatorReplacesAcrossOriginators(t *testing.T) {
	first := cpEvent(1, 200, "2001:db8:b::1", false) // originator A, pref 200
	second := cpEvent(1, 100, "2001:db8:b::2", false)
	second.Path.Originator = srpolicy.Originator{ASN: 65001, Node: mustAddr("2001:db8::fffe")}

	fp := run(t, []srpolicy.Event{first, second})
	// 幽霊が残っていれば pref 200 の first が active のままになる
	if got := fp.lastActive(t).BSID; got != mustAddr("2001:db8:b::2") {
		t.Fatalf("active bsid=%s, want b::2 (replacement must evict same-discriminator CP)", got)
	}
}

// 再購読(Run 2 回目)の初期 dump に現れなかった CP は synced 時に掃除される。
func TestResyncSweepsStaleCandidates(t *testing.T) {
	fp := &fakeProgrammer{}
	r := NewReconciler(sliceSource{[]srpolicy.Event{
		cpEvent(1, 100, "2001:db8:b::1", false),
		cpEvent(2, 200, "2001:db8:b::2", false),
	}}, fp, nil)
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	// 再接続後の初期 dump では disc=1 しか流れてこない(disc=2 は消えていた)
	r.source = sliceSource{[]srpolicy.Event{cpEvent(1, 100, "2001:db8:b::1", false)}}
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := fp.lastActive(t).BSID; got != mustAddr("2001:db8:b::1") {
		t.Fatalf("active bsid=%s, want b::1 (stale disc=2 must be swept)", got)
	}
}

// 別 policy が所有する BSID を持つ CP は候補から除外される(RFC 9256 §6.1)。
func TestBSIDConflictAcrossPolicies(t *testing.T) {
	other := srpolicy.Event{
		Key:      srpolicy.PolicyKey{Color: 200, Endpoint: mustAddr("2001:db8::2")},
		Withdraw: false,
		Path:     cpEvent(1, 100, "2001:db8:b::1", false).Path, // 同じ BSID
	}
	fp := run(t, []srpolicy.Event{
		cpEvent(1, 100, "2001:db8:b::1", false), // polKey が BSID を先取
		other,
	})
	if len(fp.added) != 1 {
		t.Fatalf("added=%d, want 1 (conflicting CP must not install)", len(fp.added))
	}
}

// Remove 失敗時は状態を保持し、次のイベントで撤去を再試行する。
func TestRemoveRetriedAfterFailure(t *testing.T) {
	fp := &fakeProgrammer{}
	r := NewReconciler(sliceSource{[]srpolicy.Event{
		cpEvent(1, 100, "2001:db8:b::1", false),
	}}, fp, nil)
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	fp.failRemove = true
	r.source = sliceSource{[]srpolicy.Event{cpEvent(1, 100, "2001:db8:b::1", true)}}
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fp.removed) != 0 {
		t.Fatal("remove should have failed")
	}

	// 撤去失敗後も policy 状態は残っており、無関係な withdraw 再送でも再試行される
	fp.failRemove = false
	r.source = sliceSource{[]srpolicy.Event{cpEvent(1, 100, "2001:db8:b::1", true)}}
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fp.removed) != 1 {
		t.Fatalf("removed=%d, want 1 (retry after failure)", len(fp.removed))
	}
}

// orphan GC: 初期同期後、どの CP にも claim されなかった既存 policy を削除する。
func TestOrphanGC(t *testing.T) {
	fp := &fakeProgrammer{preinstalled: []netip.Addr{
		mustAddr("2001:db8:b::1"),  // claim される
		mustAddr("2001:db8:b::99"), // orphan
	}}
	r := NewReconciler(sliceSource{[]srpolicy.Event{
		cpEvent(1, 100, "2001:db8:b::1", false),
	}}, fp, nil, WithOrphanGC())
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fp.gcRemoved) != 1 || fp.gcRemoved[0] != mustAddr("2001:db8:b::99") {
		t.Fatalf("gcRemoved=%v, want [2001:db8:b::99]", fp.gcRemoved)
	}
}

// markTransform は変換が適用されることの確認用。
type markTransform struct{ called *int }

func (m markTransform) Apply(cp srpolicy.CandidatePath) srpolicy.CandidatePath {
	*m.called++
	cp.BSID = mustAddr("2001:db8:b::ff")
	return cp
}

func TestTransformApplied(t *testing.T) {
	called := 0
	fp := run(t, []srpolicy.Event{cpEvent(1, 100, "2001:db8:b::1", false)}, WithTransform(markTransform{&called}))
	if called == 0 || len(fp.added) != 1 || fp.added[0].BSID != mustAddr("2001:db8:b::ff") {
		t.Fatalf("transform not applied: called=%d added=%+v", called, fp.added)
	}
}

// shortenTransform は 17 SID → 1 SID に圧縮する(uSID 圧縮相当)。
type shortenTransform struct{}

func (shortenTransform) Apply(cp srpolicy.CandidatePath) srpolicy.CandidatePath {
	out := cp
	out.SegmentLists = []srpolicy.SegmentList{
		{Weight: 1, SIDs: []netip.Addr{mustAddr("2001:db8:c::99")}},
	}
	return out
}

// 妥当性は変換「後」に評価される: 素のままでは SID 数超過で invalid な CP も、
// 圧縮変換で上限内に収まるなら active になれる。
func TestValidityEvaluatedAfterTransform(t *testing.T) {
	long := cpEvent(1, 100, "2001:db8:b::1", false)
	sids := make([]netip.Addr, srpolicy.MaxSIDsPerList+1)
	for i := range sids {
		sids[i] = mustAddr(fmt.Sprintf("2001:db8:c::%x", i+1))
	}
	long.Path.SegmentLists = []srpolicy.SegmentList{{Weight: 1, SIDs: sids}}

	// 変換なし → invalid で入らない
	if fp := run(t, []srpolicy.Event{long}); len(fp.added) != 0 {
		t.Fatalf("added=%d, want 0 (over MaxSIDsPerList without transform)", len(fp.added))
	}
	// 圧縮変換あり → valid になって入る
	if fp := run(t, []srpolicy.Event{long}, WithTransform(shortenTransform{})); len(fp.added) != 1 {
		t.Fatalf("added=%d, want 1 (transform shortens list below limit)", len(fp.added))
	}
}
