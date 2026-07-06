package control

import (
	"context"
	"log/slog"
	"net/netip"
	"reflect"
	"sync"

	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

// candidate は受信済み candidate path と、それを最後に見た購読世代。
// 世代は購読の張り直し(gobgp 再接続)後の初期 dump で更新されなかった
// 残骸 CP を掃除するために使う(gobgp は同一 NLRI の best 切替で旧 best の
// withdraw を流さないため、世代 sweep が無いと再接続を跨いだ残骸が残る)。
type candidate struct {
	path srpolicy.CandidatePath
	gen  uint64
}

// policyState は 1 つの SR Policy <color,endpoint> の状態。
//
// CP は discriminator をキーに保持する。gobgp の TYPE_BEST 購読では BGP best-path
// 選択が先に走るため、見える CP は 1 distinguisher につき常に 1 本であり
// (RFC 9830 §2.5)、originator が変わる best 切替は「同じ distinguisher の置換」
// として届く(旧 originator 分の withdraw は来ない)。originator をキーに含めると
// その置換で旧エントリが幽霊として残る。
type policyState struct {
	cps       map[uint32]candidate   // discriminator -> 受信済み CP
	installed srpolicy.CandidatePath // dataplane に入れている active CP(変換後)
	activeKey srpolicy.CPKey
	hasActive bool
	// dynBSID はこの SR Policy に動的に束縛した BSID(RFC 9256 §6.2.1)。
	// 一度割り当てたら active CP が替わっても policy が生きている間は維持する。
	dynBSID netip.Addr
}

// Reconciler は Source からの candidate path イベントを集約し、RFC 9256 §2.9 に従って
// active CP を選び、その変化を Programmer に反映する(failover を含む)。
//
// PolicyTransform は妥当性判定・選択の「前」に適用する。uSID 圧縮のような変換は
// headend が実際に instantiate する SID-list を変えるため、RFC 9256 §5.1 の妥当性
// (SID 数上限を含む)は変換後の姿で評価しなければならない。
type Reconciler struct {
	source     Source
	prog       Programmer
	transform  PolicyTransform
	log        *slog.Logger
	orphanGC   bool
	pool       *bsidPool
	verifySIDs bool
	resolver   SIDResolver // verifySIDs 有効時のみ非 nil (Run で解決)

	mu       sync.Mutex
	policies map[srpolicy.PolicyKey]*policyState
	// dynUsed は動的割当済み BSID(プールの二重払い出し防止)。
	dynUsed map[netip.Addr]srpolicy.PolicyKey
	// bsidOwner は instantiate 済み BSID の所有 policy。RFC 9256 §6.1 の
	// 「異なる SR Policy の CP が同じ BSID を持ってはならない」の検出に使う。
	bsidOwner map[netip.Addr]srpolicy.PolicyKey
	// orphans は dataplane に居るがまだどの policy にも claim されていない BSID。
	// 初期同期完了後、orphanGC が有効なら削除する。
	orphans map[netip.Addr]struct{}
	gen     uint64
}

// Option は Reconciler の任意設定。
type Option func(*Reconciler)

// WithTransform は妥当性判定・選択前の CP 変換を差し込む(既定は無変換)。
func WithTransform(t PolicyTransform) Option {
	return func(r *Reconciler) {
		if t != nil {
			r.transform = t
		}
	}
}

// WithOrphanGC は初期同期完了後に、BGP 側に対応する CP が無い dataplane 上の
// SR Policy を削除する(Programmer が Resyncer を満たす場合のみ有効)。
// dataplane を他の管理主体と共有している場合は有効にしないこと。
func WithOrphanGC() Option {
	return func(r *Reconciler) { r.orphanGC = true }
}

// WithBSIDPool は BSID 未指定の CP への動的 BSID 割当(RFC 9256 §6.2.1)を有効にする。
// prefix の host 部から policy ごとに 1 個払い出し、policy が消えるまで維持する。
// 注意: 割当は daemon のメモリ上のみで、再起動すると同じ policy でも別の BSID に
// なりうる(旧 BSID の残骸は -orphan-gc で回収)。
func WithBSIDPool(prefix netip.Prefix) Option {
	return func(r *Reconciler) { r.pool = newBSIDPool(prefix) }
}

// WithSIDVerification は RFC 9256 §5.1 の SID 解決チェックを有効にする。
// 各 SID-list の first SID と、V-Flag で verification を要求された SID を
// dataplane の FIB で解決できなければ、その SID-list を invalid にする。
// Programmer が SIDResolver を満たさない場合は警告して無効のまま動く。
func WithSIDVerification() Option {
	return func(r *Reconciler) { r.verifySIDs = true }
}

// NewReconciler は依存を注入して生成する。
func NewReconciler(src Source, prog Programmer, log *slog.Logger, opts ...Option) *Reconciler {
	if log == nil {
		log = slog.Default()
	}
	r := &Reconciler{
		source:    src,
		prog:      prog,
		transform: identityTransform{},
		log:       log,
		policies:  map[srpolicy.PolicyKey]*policyState{},
		bsidOwner: map[netip.Addr]srpolicy.PolicyKey{},
		orphans:   map[netip.Addr]struct{}{},
		dynUsed:   map[netip.Addr]srpolicy.PolicyKey{},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Run はイベント購読を開始し、ctx 終了まで反映し続ける。
// 呼び出しごとに購読世代を進め、初期同期完了(synced)時に前世代の残骸 CP を
// 掃除する。dataplane の再同期(既存 policy の把握と orphan 回収)も行う。
// ストリーム断で戻った後に再度呼んでよい(状態は保持される)。
func (r *Reconciler) Run(ctx context.Context) error {
	r.mu.Lock()
	r.gen++
	r.refreshOrphans()
	if r.verifySIDs && r.resolver == nil {
		if res, ok := r.prog.(SIDResolver); ok {
			r.resolver = res
		} else {
			r.log.Warn("SID verification requested but programmer cannot resolve SIDs; disabled")
			r.verifySIDs = false
		}
	}
	r.mu.Unlock()
	return r.source.Subscribe(ctx, r.apply, r.synced)
}

// refreshOrphans は dataplane の既存 BSID を列挙し、自分が所有していないものを
// orphan 候補として控える。r.mu を保持して呼ぶこと。
func (r *Reconciler) refreshOrphans() {
	rs, ok := r.prog.(Resyncer)
	if !ok {
		return
	}
	bsids, err := rs.InstalledBSIDs()
	if err != nil {
		r.log.Warn("list installed SR policies for resync", "err", err)
		return
	}
	r.orphans = map[netip.Addr]struct{}{}
	for _, b := range bsids {
		if _, owned := r.bsidOwner[b]; !owned {
			r.orphans[b] = struct{}{}
		}
	}
	if len(r.orphans) > 0 {
		r.log.Info("found pre-existing SR policies in dataplane",
			"count", len(r.orphans), "orphan_gc", r.orphanGC)
	}
}

// apply は candidate path の追加/削除を状態へ反映し、SR Policy を再評価する。
func (r *Reconciler) apply(ev srpolicy.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ps := r.policies[ev.Key]
	if ps == nil {
		ps = &policyState{cps: map[uint32]candidate{}}
		r.policies[ev.Key] = ps
	}

	if ev.Withdraw {
		delete(ps.cps, ev.Path.Discriminator)
	} else {
		ps.cps[ev.Path.Discriminator] = candidate{path: ev.Path, gen: r.gen}
	}

	r.reconcile(ev.Key, ps)

	if len(ps.cps) == 0 && !ps.hasActive {
		r.releaseDynBSID(ps)
		delete(r.policies, ev.Key)
	}
}

// synced は初期同期完了時に呼ばれる。前世代の残骸 CP を掃除し、
// orphanGC が有効なら誰にも claim されなかった dataplane 上の policy を削除する。
func (r *Reconciler) synced() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for key, ps := range r.policies {
		dirty := false
		for disc, c := range ps.cps {
			if c.gen < r.gen {
				delete(ps.cps, disc)
				dirty = true
			}
		}
		if dirty {
			r.log.Info("swept stale candidate paths after resync", "policy", key.String())
			r.reconcile(key, ps)
			if len(ps.cps) == 0 && !ps.hasActive {
				r.releaseDynBSID(ps)
				delete(r.policies, key)
			}
		}
	}

	if !r.orphanGC {
		r.orphans = map[netip.Addr]struct{}{}
		return
	}
	rs, ok := r.prog.(Resyncer)
	if !ok {
		return
	}
	for bsid := range r.orphans {
		if err := rs.RemoveBSID(bsid); err != nil {
			r.log.Error("remove orphan SR policy", "bsid", bsid, "err", err)
			continue
		}
		r.log.Info("removed orphan SR policy", "bsid", bsid)
		delete(r.orphans, bsid)
	}
}

// verifySegmentLists は各 SID-list の first SID と V-Flag 要求 SID を FIB で解決し、
// 解決できない list に Unresolvable を立てたコピーを返す(RFC 9256 §5.1)。
// 解決の照会自体に失敗した場合は fail-open(到達可能扱い + 警告)にする。
// r.mu を保持して呼ぶこと。
func (r *Reconciler) verifySegmentLists(key srpolicy.PolicyKey, sls []srpolicy.SegmentList, cache map[netip.Addr]bool) []srpolicy.SegmentList {
	reachable := func(sid netip.Addr) bool {
		if v, hit := cache[sid]; hit {
			return v
		}
		ok, err := r.resolver.SIDReachable(sid)
		if err != nil {
			r.log.Warn("SID reachability lookup failed; assuming reachable", "sid", sid, "err", err)
			ok = true
		}
		cache[sid] = ok
		return ok
	}

	out := make([]srpolicy.SegmentList, len(sls))
	for i, sl := range sls {
		out[i] = sl
		if len(sl.SIDs) == 0 {
			continue
		}
		for j, sid := range sl.SIDs {
			// first SID は常に、それ以外は V-Flag が立っている場合のみ検証(§5.1)
			if j != 0 && (j >= 32 || sl.VerifyMask&(1<<uint(j)) == 0) {
				continue
			}
			if !reachable(sid) {
				r.log.Warn("segment list invalid: SID unresolvable in FIB (RFC 9256 §5.1)",
					"policy", key.String(), "sid", sid, "position", j)
				out[i].Unresolvable = true
				break
			}
		}
	}
	return out
}

// ensureDynBSID は policy に動的 BSID を割り当てる(割当済みなら何もしない)。
// r.mu を保持して呼ぶこと。
func (r *Reconciler) ensureDynBSID(key srpolicy.PolicyKey, ps *policyState) bool {
	if ps.dynBSID.IsValid() {
		return true
	}
	bsid, ok := r.pool.alloc(func(a netip.Addr) bool {
		if _, used := r.bsidOwner[a]; used {
			return true
		}
		if _, used := r.dynUsed[a]; used {
			return true
		}
		_, used := r.orphans[a]
		return used
	})
	if !ok {
		r.log.Error("BSID pool exhausted; candidate path excluded", "policy", key.String())
		return false
	}
	ps.dynBSID = bsid
	r.dynUsed[bsid] = key
	r.log.Info("dynamically bound BSID (RFC 9256 §6.2.1)", "policy", key.String(), "bsid", bsid)
	return true
}

// releaseDynBSID は policy 削除時に動的 BSID をプールへ返す。r.mu を保持して呼ぶこと。
func (r *Reconciler) releaseDynBSID(ps *policyState) {
	if ps.dynBSID.IsValid() {
		delete(r.dynUsed, ps.dynBSID)
		ps.dynBSID = netip.Addr{}
	}
}

// reconcile は active CP を選び直し、instantiate 済みとの差分を Programmer に反映する。
// r.mu を保持して呼ぶこと。
func (r *Reconciler) reconcile(key srpolicy.PolicyKey, ps *policyState) {
	// 変換(uSID 圧縮など)を全 CP に適用してから妥当性・選択を評価する。
	// 他 policy が所有する BSID を持つ CP は候補から除外する(RFC 9256 §6.1)。
	reach := map[netip.Addr]bool{} // この reconcile 内での到達性 lookup キャッシュ
	cps := make([]srpolicy.CandidatePath, 0, len(ps.cps))
	for _, c := range ps.cps {
		t := r.transform.Apply(c.path)
		if r.verifySIDs {
			t.SegmentLists = r.verifySegmentLists(key, t.SegmentLists, reach)
		}
		if !t.HasBSID() && !t.SpecifiedBSIDOnly {
			if r.pool == nil {
				r.log.Warn("candidate path has no BSID and no -bsid-pool configured; excluded",
					"policy", key.String(), "discriminator", t.Discriminator)
				continue
			}
			if !r.ensureDynBSID(key, ps) {
				continue
			}
			t.BSID = ps.dynBSID // 動的 BSID は policy が生きている間固定 (§6.2.1)
		}
		if owner, taken := r.bsidOwner[t.BSID]; taken && owner != key {
			// RFC 9256 §6.2: BSID が使用不可のときは alert を出さなければならない。
			r.log.Error("BSID conflict: candidate path excluded",
				"policy", key.String(), "bsid", t.BSID, "owned_by", owner.String(),
				"discriminator", t.Discriminator)
			continue
		}
		cps = append(cps, t)
	}

	active, ok := srpolicy.SelectActive(cps, ps.activeKey, ps.hasActive)
	if !ok {
		// valid な CP が無い → SR Policy ダウン。instantiate 済みなら撤去。
		if !ps.hasActive {
			return
		}
		if ps.installed.DropUponInvalid {
			r.log.Warn("drop-upon-invalid (I-Flag) requested but not supported by dataplane; falling back to removal",
				"policy", key.String())
		}
		if err := r.prog.Remove(key, ps.installed); err != nil {
			// 状態は保持して次のイベントで撤去を再試行する(忘れると dataplane に
			// policy が残ったまま管理から漏れる)。
			r.log.Error("remove (no valid CP); will retry on next event",
				"policy", key.String(), "err", err)
			return
		}
		r.log.Info("policy down (no valid candidate path)", "policy", key.String())
		delete(r.bsidOwner, ps.installed.BSID)
		ps.hasActive = false
		ps.activeKey = srpolicy.CPKey{}
		return
	}

	if ps.hasActive && ps.activeKey == active.Key() && sameInstall(ps.installed, active) {
		return // 変化なし
	}

	if ps.hasActive {
		if err := r.prog.Replace(key, ps.installed, active); err != nil {
			r.log.Error("replace active candidate path; keeping previous",
				"policy", key.String(), "err", err)
			return // 旧 CP が生きている前提で状態を保持
		}
		delete(r.bsidOwner, ps.installed.BSID)
	} else {
		if err := r.prog.Add(key, active); err != nil {
			r.log.Error("add", "policy", key.String(), "err", err)
			return
		}
	}
	r.bsidOwner[active.BSID] = key
	delete(r.orphans, active.BSID) // 再同期中の既存 policy を claim
	ps.installed = active
	ps.activeKey = active.Key()
	ps.hasActive = true
	r.log.Info("active candidate path installed",
		"policy", key.String(), "bsid", active.BSID,
		"preference", active.Preference, "discriminator", active.Discriminator,
		"origin", active.Origin, "segment_lists", len(active.ValidSegmentLists()),
		"candidates", len(cps))
}

func sameInstall(a, b srpolicy.CandidatePath) bool {
	return a.BSID == b.BSID && reflect.DeepEqual(a.SegmentLists, b.SegmentLists)
}
