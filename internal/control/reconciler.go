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
}

// Reconciler は Source からの candidate path イベントを集約し、RFC 9256 §2.9 に従って
// active CP を選び、その変化を Programmer に反映する(failover を含む)。
//
// PolicyTransform は妥当性判定・選択の「前」に適用する。uSID 圧縮のような変換は
// headend が実際に instantiate する SID-list を変えるため、RFC 9256 §5.1 の妥当性
// (SID 数上限を含む)は変換後の姿で評価しなければならない。
type Reconciler struct {
	source    Source
	prog      Programmer
	transform PolicyTransform
	log       *slog.Logger
	orphanGC  bool

	mu       sync.Mutex
	policies map[srpolicy.PolicyKey]*policyState
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

// reconcile は active CP を選び直し、instantiate 済みとの差分を Programmer に反映する。
// r.mu を保持して呼ぶこと。
func (r *Reconciler) reconcile(key srpolicy.PolicyKey, ps *policyState) {
	// 変換(uSID 圧縮など)を全 CP に適用してから妥当性・選択を評価する。
	// 他 policy が所有する BSID を持つ CP は候補から除外する(RFC 9256 §6.1)。
	cps := make([]srpolicy.CandidatePath, 0, len(ps.cps))
	for _, c := range ps.cps {
		t := r.transform.Apply(c.path)
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
