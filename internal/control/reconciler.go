package control

import (
	"context"
	"log/slog"

	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

// Reconciler は Source から受けた SR Policy イベントを Programmer に反映する。
// 具体実装に依存しないため、テストでは fake を注入できる。
type Reconciler struct {
	source    Source
	prog      Programmer
	store     Store
	transform PolicyTransform
	log       *slog.Logger
}

// Option は Reconciler の任意設定。
type Option func(*Reconciler)

// WithTransform は投入前の Policy 変換を差し込む(既定は無変換)。
func WithTransform(t PolicyTransform) Option {
	return func(r *Reconciler) {
		if t != nil {
			r.transform = t
		}
	}
}

// NewReconciler は依存(供給源・投入先・状態ストア・logger)を注入して生成する。
func NewReconciler(src Source, prog Programmer, store Store, log *slog.Logger, opts ...Option) *Reconciler {
	if log == nil {
		log = slog.Default()
	}
	r := &Reconciler{
		source:    src,
		prog:      prog,
		store:     store,
		transform: identityTransform{},
		log:       log,
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

// apply は 1 イベントを処理する。Subscribe から逐次(単一 goroutine)で呼ばれる前提。
func (r *Reconciler) apply(ev srpolicy.Event) {
	// withdraw は NLRI のキーだけで引けるため変換不要。
	if ev.Withdraw {
		r.withdraw(ev.Policy.Key())
		return
	}

	// 投入前の変換(uSID 圧縮など)。変換は NLRI キーを変えない。
	p := r.transform.Apply(ev.Policy)
	key := p.Key()

	if err := p.ValidateSRv6(); err != nil {
		r.log.Warn("skip policy", "key", key, "reason", err)
		return
	}
	// 更新を冪等にするため、既存があれば一旦消してから入れ直す。
	if old, ok := r.store.Get(key); ok {
		if err := r.prog.Remove(old); err != nil {
			r.log.Error("remove (update)", "key", key, "err", err)
		}
		r.store.Delete(key)
	}
	if err := r.prog.Add(p); err != nil {
		r.log.Error("add", "key", key, "err", err)
		return
	}
	r.store.Put(p)
	r.log.Info("added",
		"color", p.Color, "endpoint", p.Endpoint, "bsid", p.BSID,
		"preference", p.Preference, "segment_lists", len(p.SegmentLists))
}

func (r *Reconciler) withdraw(key srpolicy.Key) {
	old, ok := r.store.Get(key)
	if !ok {
		return
	}
	if err := r.prog.Remove(old); err != nil {
		r.log.Error("remove", "key", key, "err", err)
	} else {
		r.log.Info("withdrawn", "color", old.Color, "endpoint", old.Endpoint, "bsid", old.BSID)
	}
	r.store.Delete(key)
}
