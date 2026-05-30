package control

import (
	"context"
	"log/slog"
	"reflect"

	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

// policyState は 1 つの SR Policy <color,endpoint> の状態。
type policyState struct {
	cps       map[srpolicy.CPKey]srpolicy.CandidatePath // 受信済み candidate path 群
	installed srpolicy.CandidatePath                    // VPP に入れている active CP(変換後)
	activeKey srpolicy.CPKey
	hasActive bool
}

// Reconciler は Source からの candidate path イベントを集約し、RFC 9256 §2.9 に従って
// active CP を選び、その変化を Programmer に反映する(failover を含む)。
type Reconciler struct {
	source    Source
	prog      Programmer
	transform PolicyTransform
	log       *slog.Logger
	policies  map[srpolicy.PolicyKey]*policyState
}

// Option は Reconciler の任意設定。
type Option func(*Reconciler)

// WithTransform は active CP の instantiate 前変換を差し込む(既定は無変換)。
func WithTransform(t PolicyTransform) Option {
	return func(r *Reconciler) {
		if t != nil {
			r.transform = t
		}
	}
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
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Run はイベント購読を開始し、ctx 終了まで反映し続ける。
func (r *Reconciler) Run(ctx context.Context) error {
	return r.source.Subscribe(ctx, r.apply)
}

// apply は candidate path の追加/削除を状態へ反映し、SR Policy を再評価する。
func (r *Reconciler) apply(ev srpolicy.Event) {
	ps := r.policies[ev.Key]
	if ps == nil {
		ps = &policyState{cps: map[srpolicy.CPKey]srpolicy.CandidatePath{}}
		r.policies[ev.Key] = ps
	}

	cpKey := ev.Path.Key()
	if ev.Withdraw {
		delete(ps.cps, cpKey)
	} else {
		ps.cps[cpKey] = ev.Path
	}

	r.reconcile(ev.Key, ps)

	if len(ps.cps) == 0 && !ps.hasActive {
		delete(r.policies, ev.Key)
	}
}

// reconcile は active CP を選び直し、instantiate 済みとの差分を Programmer に反映する。
func (r *Reconciler) reconcile(key srpolicy.PolicyKey, ps *policyState) {
	cps := make([]srpolicy.CandidatePath, 0, len(ps.cps))
	for _, cp := range ps.cps {
		cps = append(cps, cp)
	}

	active, ok := srpolicy.SelectActive(cps, ps.activeKey, ps.hasActive)
	if !ok {
		// valid な CP が無い → SR Policy ダウン。instantiate 済みなら撤去。
		if ps.hasActive {
			if err := r.prog.Remove(ps.installed); err != nil {
				r.log.Error("remove (no valid CP)", "policy", key.String(), "err", err)
			} else {
				r.log.Info("policy down (no valid candidate path)", "policy", key.String())
			}
			ps.hasActive = false
			ps.activeKey = srpolicy.CPKey{}
		}
		return
	}

	desired := r.transform.Apply(active)
	if ps.hasActive && ps.activeKey == active.Key() && sameInstall(ps.installed, desired) {
		return // 変化なし
	}

	// active CP の切替 or 内容更新。BSID が変わりうるので 旧を消して新を入れる。
	if ps.hasActive {
		if err := r.prog.Remove(ps.installed); err != nil {
			r.log.Error("remove (switch)", "policy", key.String(), "err", err)
		}
	}
	if err := r.prog.Add(desired); err != nil {
		r.log.Error("add", "policy", key.String(), "err", err)
		ps.hasActive = false
		return
	}
	ps.installed = desired
	ps.activeKey = active.Key()
	ps.hasActive = true
	r.log.Info("active candidate path installed",
		"policy", key.String(), "bsid", desired.BSID,
		"preference", active.Preference, "discriminator", active.Discriminator,
		"origin", active.Origin, "segment_lists", len(desired.ValidSegmentLists()),
		"candidates", len(cps))
}

func sameInstall(a, b srpolicy.CandidatePath) bool {
	return a.BSID == b.BSID && reflect.DeepEqual(a.SegmentLists, b.SegmentLists)
}
