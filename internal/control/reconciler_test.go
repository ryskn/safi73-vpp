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

	unreachable map[netip.Addr]bool // SIDReachable が false を返す SID
	resolveErr  error               // SIDReachable が返すエラー

	dropInstalled []srpolicy.PolicyKey // InstallDrop された policy
	dropRemoved   []srpolicy.PolicyKey // RemoveDrop された policy
	failDrop      bool
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

func (f *fakeProgrammer) SIDReachable(sid netip.Addr) (bool, error) {
	if f.resolveErr != nil {
		return false, f.resolveErr
	}
	return !f.unreachable[sid], nil
}

func (f *fakeProgrammer) InstallDrop(key srpolicy.PolicyKey) error {
	if f.failDrop {
		return fmt.Errorf("drop failed")
	}
	f.dropInstalled = append(f.dropInstalled, key)
	return nil
}

func (f *fakeProgrammer) RemoveDrop(key srpolicy.PolicyKey) error {
	f.dropRemoved = append(f.dropRemoved, key)
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

// BSID 無し CP: プール設定時は動的割当され、active CP が替わっても BSID は維持される
// (RFC 9256 §6.2.1)。プール無しでは候補外。
func TestDynamicBSIDAllocation(t *testing.T) {
	pool := netip.MustParsePrefix("2001:db8:dddd::/64")
	noBSID := func(disc, pref uint32) srpolicy.Event {
		ev := cpEvent(disc, pref, "2001:db8:b::1", false)
		ev.Path.BSID = netip.Addr{}
		return ev
	}

	// プール無し → 候補外
	if fp := run(t, []srpolicy.Event{noBSID(1, 100)}); len(fp.added) != 0 {
		t.Fatalf("added=%d, want 0 without pool", len(fp.added))
	}

	// プール有り → 割当されて install、CP 切替でも同じ BSID
	fp := run(t, []srpolicy.Event{noBSID(1, 100), noBSID(2, 200)}, WithBSIDPool(pool))
	if len(fp.added) != 1 {
		t.Fatalf("added=%d, want 1", len(fp.added))
	}
	got := fp.added[0].BSID
	if !pool.Contains(got) {
		t.Fatalf("allocated bsid=%s not in pool %s", got, pool)
	}
	if len(fp.replaced) != 1 || fp.replaced[0][1].BSID != got {
		t.Fatalf("dynamic BSID must be stable across CP switch: %+v", fp.replaced)
	}
}

// S-Flag (Specified-BSID-only) 付きで BSID 未指定の CP は、プールがあっても invalid。
func TestSpecifiedBSIDOnlyWithoutBSID(t *testing.T) {
	ev := cpEvent(1, 100, "2001:db8:b::1", false)
	ev.Path.BSID = netip.Addr{}
	ev.Path.SpecifiedBSIDOnly = true
	fp := run(t, []srpolicy.Event{ev}, WithBSIDPool(netip.MustParsePrefix("2001:db8:dddd::/64")))
	if len(fp.added) != 0 {
		t.Fatalf("added=%d, want 0 (S-Flag forbids dynamic allocation)", len(fp.added))
	}
}

// 動的 BSID は policy 消滅で解放され、次の policy が再利用できる。
func TestDynamicBSIDReleasedOnPolicyDelete(t *testing.T) {
	pool := netip.MustParsePrefix("2001:db8:dddd::/126") // host 2bit = 3 個しか無い極小プール
	noBSID := func(withdraw bool) srpolicy.Event {
		ev := cpEvent(1, 100, "2001:db8:b::1", withdraw)
		ev.Path.BSID = netip.Addr{}
		return ev
	}
	fp := &fakeProgrammer{}
	r := NewReconciler(sliceSource{[]srpolicy.Event{noBSID(false), noBSID(true)}}, fp, nil, WithBSIDPool(pool))
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.dynUsed) != 0 {
		t.Fatalf("dynUsed=%v, want released after policy delete", r.dynUsed)
	}
}

// SID 到達性検証 (RFC 9256 §5.1): first SID が FIB で解決できない SID-list は invalid。
func TestSIDVerification(t *testing.T) {
	sid := mustAddr("2001:db8:c::1")

	// first SID 到達不能 → CP invalid → install されない
	fp := &fakeProgrammer{unreachable: map[netip.Addr]bool{sid: true}}
	r := NewReconciler(sliceSource{[]srpolicy.Event{cpEvent(1, 100, "2001:db8:b::1", false)}},
		fp, nil, WithSIDVerification())
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fp.added) != 0 {
		t.Fatalf("added=%d, want 0 (unreachable first SID)", len(fp.added))
	}

	// 到達可能なら install される
	fp = &fakeProgrammer{}
	r = NewReconciler(sliceSource{[]srpolicy.Event{cpEvent(1, 100, "2001:db8:b::1", false)}},
		fp, nil, WithSIDVerification())
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fp.added) != 1 {
		t.Fatalf("added=%d, want 1 (reachable)", len(fp.added))
	}
}

// V-Flag 付きの非 first SID も検証対象。V-Flag 無しの非 first SID は検証しない。
func TestSIDVerificationVFlag(t *testing.T) {
	second := mustAddr("2001:db8:c::2")
	ev := cpEvent(1, 100, "2001:db8:b::1", false)
	ev.Path.SegmentLists = []srpolicy.SegmentList{{
		Weight: 1,
		SIDs:   []netip.Addr{mustAddr("2001:db8:c::1"), second},
	}}

	// V-Flag 無し: 2 番目が到達不能でも install される
	fp := &fakeProgrammer{unreachable: map[netip.Addr]bool{second: true}}
	r := NewReconciler(sliceSource{[]srpolicy.Event{ev}}, fp, nil, WithSIDVerification())
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fp.added) != 1 {
		t.Fatalf("added=%d, want 1 (no V-Flag on second SID)", len(fp.added))
	}

	// V-Flag 有り: 2 番目の到達不能で invalid
	ev.Path.SegmentLists[0].VerifyMask = 1 << 1
	fp = &fakeProgrammer{unreachable: map[netip.Addr]bool{second: true}}
	r = NewReconciler(sliceSource{[]srpolicy.Event{ev}}, fp, nil, WithSIDVerification())
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fp.added) != 0 {
		t.Fatalf("added=%d, want 0 (V-Flag SID unreachable)", len(fp.added))
	}
}

// 到達性の照会自体が失敗したら fail-open (install する)。
func TestSIDVerificationFailOpen(t *testing.T) {
	fp := &fakeProgrammer{resolveErr: fmt.Errorf("vpp down")}
	r := NewReconciler(sliceSource{[]srpolicy.Event{cpEvent(1, 100, "2001:db8:b::1", false)}},
		fp, nil, WithSIDVerification())
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fp.added) != 1 {
		t.Fatalf("added=%d, want 1 (fail-open on lookup error)", len(fp.added))
	}
}

// drop-upon-invalid (I-Flag, RFC 9256 §8.2):
// invalid 化 → 削除 + drop 投入 / 復帰 → drop 解除 + 再投入 / 全 withdraw → drop 撤去。
func TestDropUponInvalid(t *testing.T) {
	valid := cpEvent(1, 100, "2001:db8:b::1", false)
	valid.Path.DropUponInvalid = true
	invalid := cpEvent(1, 100, "2001:db8:b::1", false)
	invalid.Path.DropUponInvalid = true
	invalid.Path.SegmentLists = []srpolicy.SegmentList{{Weight: 0, SIDs: []netip.Addr{mustAddr("2001:db8:c::1")}}}

	// valid → invalid: policy 削除 + drop 発動
	fp := run(t, []srpolicy.Event{valid, invalid})
	if len(fp.removed) != 1 || len(fp.dropInstalled) != 1 || fp.dropInstalled[0] != polKey {
		t.Fatalf("removed=%d dropInstalled=%v, want removal + drop engaged", len(fp.removed), fp.dropInstalled)
	}

	// invalid → valid: drop 解除してから再投入
	fp = run(t, []srpolicy.Event{valid, invalid, valid})
	if len(fp.dropRemoved) != 1 || len(fp.added) != 2 {
		t.Fatalf("dropRemoved=%d added=%d, want drop released then reinstalled", len(fp.dropRemoved), len(fp.added))
	}

	// 全 withdraw: policy 消滅 → drop も撤去される (fail-closed の根拠が無くなる)
	wd := cpEvent(1, 100, "2001:db8:b::1", true)
	fp = run(t, []srpolicy.Event{valid, invalid, wd})
	if len(fp.dropRemoved) != 1 {
		t.Fatalf("dropRemoved=%d, want drop removed when policy ceases to exist", len(fp.dropRemoved))
	}
}

// I-Flag 無しの CP は従来どおり削除のみ (IGP フォールバック)。
func TestNoDropWithoutIFlag(t *testing.T) {
	fp := run(t, []srpolicy.Event{
		cpEvent(1, 100, "2001:db8:b::1", false),
		cpEvent(1, 100, "2001:db8:b::1", true),
	})
	if len(fp.dropInstalled) != 0 {
		t.Fatalf("dropInstalled=%v, want none without I-Flag", fp.dropInstalled)
	}
}

// drop 投入に失敗したら既定動作 (削除のみ) にフォールバックし、状態は down のまま。
func TestDropFailureFallsBackToRemoval(t *testing.T) {
	valid := cpEvent(1, 100, "2001:db8:b::1", false)
	valid.Path.DropUponInvalid = true
	fp := &fakeProgrammer{failDrop: true}
	r := NewReconciler(sliceSource{[]srpolicy.Event{
		valid,
		cpEvent(1, 100, "2001:db8:b::1", true),
	}}, fp, nil)
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fp.removed) != 1 || len(fp.dropInstalled) != 0 {
		t.Fatalf("removed=%d dropInstalled=%d, want removal only", len(fp.removed), len(fp.dropInstalled))
	}
}

// 再検証は priority 順 (低い値 = 高優先, RFC 9256 §2.12)。
// FIB 変化 (SID 到達性) を再検証で拾い、priority の低い policy から処理される。
func TestRevalidationInPriorityOrder(t *testing.T) {
	sidHi := mustAddr("2001:db8:c::1") // 高優先 policy (priority 10) の first SID
	sidLo := mustAddr("2001:db8:c::2") // 低優先 policy (priority 200) の first SID

	evHi := cpEvent(1, 100, "2001:db8:b::1", false)
	evHi.Path.Priority = 10
	evHi.Path.SegmentLists = []srpolicy.SegmentList{{Weight: 1, SIDs: []netip.Addr{sidHi}}}
	evLo := srpolicy.Event{
		Key:  srpolicy.PolicyKey{Color: 200, Endpoint: mustAddr("2001:db8::2")},
		Path: evHi.Path,
	}
	evLo.Path.Priority = 200
	evLo.Path.SegmentLists = []srpolicy.SegmentList{{Weight: 1, SIDs: []netip.Addr{sidLo}}}
	evLo.Path.BSID = mustAddr("2001:db8:b::2")

	fp := &fakeProgrammer{unreachable: map[netip.Addr]bool{}}
	r := NewReconciler(sliceSource{[]srpolicy.Event{evHi, evLo}}, fp, nil, WithSIDVerification())
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fp.added) != 2 {
		t.Fatalf("added=%d, want both installed first", len(fp.added))
	}

	// FIB から両方の first SID が消えた → 再検証で両 policy down。
	// 撤去は priority 10 の policy (b::1) が先でなければならない。
	fp.unreachable[sidHi] = true
	fp.unreachable[sidLo] = true
	r.revalidateAll()
	if len(fp.removed) != 2 {
		t.Fatalf("removed=%d, want 2 after revalidation", len(fp.removed))
	}
	if fp.removed[0].BSID != mustAddr("2001:db8:b::1") {
		t.Fatalf("first removed=%s, want priority-10 policy (b::1) first", fp.removed[0].BSID)
	}

	// FIB 復旧 → 再検証で再インストール (同じく priority 順)
	delete(fp.unreachable, sidHi)
	delete(fp.unreachable, sidLo)
	r.revalidateAll()
	if len(fp.added) != 4 {
		t.Fatalf("added=%d, want reinstalled on recovery", len(fp.added))
	}
	if fp.added[2].BSID != mustAddr("2001:db8:b::1") {
		t.Fatalf("first reinstalled=%s, want priority-10 policy first", fp.added[2].BSID)
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
